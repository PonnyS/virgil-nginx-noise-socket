package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	apiListenAddr       = "127.0.0.1:7990"
	websocketListenAddr = "127.0.0.1:7991"
	downloadListenAddr  = "127.0.0.1:7992"
	readBodyLimit       = 1 << 20
	shutdownTimeout     = 5 * time.Second
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(_ *http.Request) bool {
		return true
	},
}

type namedServer struct {
	name   string
	server *http.Server
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	writtenSize int
}

type apiEchoResponse struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	RawQuery   string            `json:"raw_query"`
	Body       string            `json:"body"`
	Headers    map[string]string `json:"headers"`
	RemoteAddr string            `json:"remote_addr"`
	ReceivedAt string            `json:"received_at"`
}

// main 启动三个后端服务，并在收到退出信号时执行优雅关闭。
func main() {
	servers := []namedServer{
		{
			name:   "api-server",
			server: buildAPIServer(),
		},
		{
			name:   "ws-server",
			server: buildWebSocketServer(),
		},
		{
			name:   "download-server",
			server: buildDownloadServer(),
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, len(servers))
	var wg sync.WaitGroup
	startServers(servers, errCh, &wg)

	var runErr error
	select {
	case <-ctx.Done():
		log.Printf("收到退出信号: %v", ctx.Err())
	case runErr = <-errCh:
		log.Printf("服务运行异常: %v", runErr)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	shutdownServers(shutdownCtx, servers)
	wg.Wait()

	if runErr != nil {
		os.Exit(1)
	}
}

// buildAPIServer 构建处理 /api/echo 的 HTTP 服务。
func buildAPIServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/echo", handleAPIEcho)

	return &http.Server{
		Addr:              apiListenAddr,
		Handler:           accessLogMiddleware("api-server", mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// buildWebSocketServer 构建处理 /ws/echo 的 websocket 服务。
func buildWebSocketServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/echo", handleWebSocketEcho)

	return &http.Server{
		Addr:              websocketListenAddr,
		Handler:           accessLogMiddleware("ws-server", mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// buildDownloadServer 构建处理 /download/dl 的下载服务。
func buildDownloadServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/download/dl", handleDownload)

	return &http.Server{
		Addr:              downloadListenAddr,
		Handler:           accessLogMiddleware("download-server", mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// startServers 并发启动多个 HTTP 服务。
func startServers(servers []namedServer, errCh chan<- error, wg *sync.WaitGroup) {
	for _, server := range servers {
		startServer(server, errCh, wg)
	}
}

// startServer 启动单个 HTTP 服务并上报异常。
func startServer(server namedServer, errCh chan<- error, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		log.Printf("%s 监听 %s", server.name, server.server.Addr)
		err := server.server.ListenAndServe()
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return
		}

		select {
		case errCh <- fmt.Errorf("%s 启动失败: %w", server.name, err):
		default:
		}
	}()
}

// shutdownServers 依次优雅关闭所有 HTTP 服务。
func shutdownServers(ctx context.Context, servers []namedServer) {
	for _, server := range servers {
		if err := server.server.Shutdown(ctx); err != nil {
			log.Printf("%s 关闭失败: %v", server.name, err)
			continue
		}
		log.Printf("%s 已关闭", server.name)
	}
}

// handleAPIEcho 返回请求关键信息，用于联调 /api/echo。
func handleAPIEcho(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/api/echo" {
		http.NotFound(writer, request)
		return
	}

	body, err := io.ReadAll(io.LimitReader(request.Body, readBodyLimit))
	if err != nil {
		http.Error(writer, "read request body failed", http.StatusBadRequest)
		return
	}

	requestID := getOrCreateRequestID(request)
	log.Printf(
		"api_echo_request request_id=%s method=%s path=%s query=%q body_bytes=%d body_preview=%q remote_addr=%s",
		requestID,
		request.Method,
		request.URL.Path,
		request.URL.RawQuery,
		len(body),
		previewString(string(body), 256),
		request.RemoteAddr,
	)

	response := apiEchoResponse{
		Method:     request.Method,
		Path:       request.URL.Path,
		RawQuery:   request.URL.RawQuery,
		Body:       string(body),
		Headers:    buildHeaderMap(request),
		RemoteAddr: request.RemoteAddr,
		ReceivedAt: time.Now().Format(time.RFC3339),
	}

	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		log.Printf("handleAPIEcho 写响应失败: %v", err)
	}
}

// handleWebSocketEcho 建立 websocket 连接并回显收到的消息。
func handleWebSocketEcho(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/ws/echo" {
		http.NotFound(writer, request)
		return
	}

	requestID := getOrCreateRequestID(request)
	connection, err := wsUpgrader.Upgrade(writer, request, nil)
	if err != nil {
		log.Printf(
			"ws_upgrade_failed request_id=%s remote_addr=%s err=%v",
			requestID,
			request.RemoteAddr,
			err,
		)
		return
	}
	defer connection.Close()

	log.Printf(
		"ws_upgrade_success request_id=%s remote_addr=%s subprotocol=%s",
		requestID,
		request.RemoteAddr,
		connection.Subprotocol(),
	)

	connection.SetReadLimit(readBodyLimit)

	for {
		messageType, payload, err := connection.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf(
					"ws_close request_id=%s remote_addr=%s reason=normal",
					requestID,
					request.RemoteAddr,
				)
				return
			}
			log.Printf(
				"ws_read_failed request_id=%s remote_addr=%s err=%v",
				requestID,
				request.RemoteAddr,
				err,
			)
			return
		}

		log.Printf(
			"ws_read request_id=%s remote_addr=%s message_type=%d payload_bytes=%d payload_preview=%q",
			requestID,
			request.RemoteAddr,
			messageType,
			len(payload),
			previewString(string(payload), 256),
		)

		if err := connection.WriteMessage(messageType, payload); err != nil {
			log.Printf(
				"ws_write_failed request_id=%s remote_addr=%s err=%v",
				requestID,
				request.RemoteAddr,
				err,
			)
			return
		}

		log.Printf(
			"ws_write request_id=%s remote_addr=%s message_type=%d payload_bytes=%d",
			requestID,
			request.RemoteAddr,
			messageType,
			len(payload),
		)
	}
}

// handleDownload 返回下载响应，用于联调 /download/dl。
func handleDownload(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/download/dl" {
		http.NotFound(writer, request)
		return
	}

	requestID := getOrCreateRequestID(request)
	content := []byte("noise demo download file\n")
	fileName := "noise-demo.txt"

	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Disposition", `attachment; filename="`+fileName+`"`)
	writer.Header().Set("Content-Length", strconv.Itoa(len(content)))

	if _, err := writer.Write(content); err != nil {
		log.Printf("handleDownload 写响应失败: %v", err)
		return
	}

	log.Printf(
		"download_sent request_id=%s method=%s path=%s filename=%s bytes=%d remote_addr=%s",
		requestID,
		request.Method,
		request.URL.Path,
		fileName,
		len(content),
		request.RemoteAddr,
	)
}

// buildHeaderMap 将请求头压平成 map，便于在 echo 响应中查看。
func buildHeaderMap(request *http.Request) map[string]string {
	headers := make(map[string]string, len(request.Header))
	for key, values := range request.Header {
		headers[key] = strings.Join(values, ",")
	}
	return headers
}

// accessLogMiddleware 统一记录详细访问日志，便于联调链路问题。
func accessLogMiddleware(serverName string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		startAt := time.Now()
		requestID := getOrCreateRequestID(request)

		recorder := &statusRecorder{
			ResponseWriter: writer,
			status:         http.StatusOK,
		}

		next.ServeHTTP(recorder, request)

		duration := time.Since(startAt)
		log.Printf(
			"access_log server=%s request_id=%s remote_addr=%s x_forwarded_for=%q method=%s uri=%s status=%d bytes=%d duration_ms=%d user_agent=%q referer=%q",
			serverName,
			requestID,
			request.RemoteAddr,
			request.Header.Get("X-Forwarded-For"),
			request.Method,
			request.URL.RequestURI(),
			recorder.status,
			recorder.writtenSize,
			duration.Milliseconds(),
			request.UserAgent(),
			request.Referer(),
		)
	})
}

// WriteHeader 记录响应状态码。
func (recorder *statusRecorder) WriteHeader(statusCode int) {
	recorder.status = statusCode
	recorder.ResponseWriter.WriteHeader(statusCode)
}

// Write 记录响应大小。
func (recorder *statusRecorder) Write(data []byte) (int, error) {
	writtenSize, err := recorder.ResponseWriter.Write(data)
	recorder.writtenSize += writtenSize
	return writtenSize, err
}

// Hijack 透传底层连接劫持能力，保证 websocket upgrade 可用。
func (recorder *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := recorder.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not implement http.Hijacker")
	}
	// websocket upgrade 通过 Hijack 写回 101，默认状态需同步为切换协议。
	if recorder.status == http.StatusOK {
		recorder.status = http.StatusSwitchingProtocols
	}
	return hijacker.Hijack()
}

// Flush 透传流式刷新能力，避免包装后丢失接口。
func (recorder *statusRecorder) Flush() {
	flusher, ok := recorder.ResponseWriter.(http.Flusher)
	if !ok {
		return
	}
	flusher.Flush()
}

// Push 透传 HTTP/2 server push 能力，不支持时返回标准错误。
func (recorder *statusRecorder) Push(target string, options *http.PushOptions) error {
	pusher, ok := recorder.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, options)
}

// getOrCreateRequestID 尝试复用 X-Request-Id，不存在时生成一个短随机 id。
func getOrCreateRequestID(request *http.Request) string {
	requestID := strings.TrimSpace(request.Header.Get("X-Request-Id"))
	if requestID != "" {
		return requestID
	}

	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return "req-" + hex.EncodeToString(randomBytes)
}

// previewString 将日志内容裁剪到指定长度，避免刷屏。
func previewString(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "...(truncated)"
}
