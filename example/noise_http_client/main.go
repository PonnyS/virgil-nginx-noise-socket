package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	noise "github.com/flynn/noise"
)

const (
	defaultNoiseProtocol  = "Noise_XX_25519_AESGCM_BLAKE2b"
	defaultNoisePrologue  = "NoiseSocketInit1"
	noiseNegotiationLen   = 6
	noiseVersionID        = 1
	noiseFrameLengthBytes = 2
	maxPlainFrameSize     = 65517

	websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

type protocolHeader struct {
	VersionID uint16
	DHID      byte
	CipherID  byte
	HashID    byte
	PatternID byte
}

type noiseProtocolConfig struct {
	Name              string
	Prologue          string
	DHName            string
	Header            protocolHeader
	KeySize           int
	CipherSuite       noise.CipherSuite
	Pattern           noise.HandshakePattern
	NeedsLocalStatic  bool
	NeedsRemoteStatic bool
}

type noiseConn struct {
	conn       net.Conn
	sendCipher *noise.CipherState
	recvCipher *noise.CipherState

	readMu  sync.Mutex
	writeMu sync.Mutex
	readBuf []byte
}

type noisePatternSpec struct {
	ID                byte
	Pattern           noise.HandshakePattern
	NeedsLocalStatic  bool
	NeedsRemoteStatic bool
}

// Read 从 Noise 帧中解密出明文，并按 net.Conn 语义返回字节流。
func (c *noiseConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuf) == 0 {
		payload, err := c.readPayloadFrame()
		if err != nil {
			return 0, err
		}
		c.readBuf = payload
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// Write 将明文拆分为 Noise 数据帧并加密发送。
func (c *noiseConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > maxPlainFrameSize {
			chunkSize = maxPlainFrameSize
		}

		chunk := p[:chunkSize]
		p = p[chunkSize:]

		plaintext := make([]byte, noiseFrameLengthBytes+len(chunk))
		binary.BigEndian.PutUint16(plaintext[:noiseFrameLengthBytes], uint16(len(chunk)))
		copy(plaintext[noiseFrameLengthBytes:], chunk)

		ciphertext, err := c.sendCipher.Encrypt(nil, nil, plaintext)
		if err != nil {
			return total, fmt.Errorf("noise encrypt failed: %w", err)
		}

		if len(ciphertext) > 0xFFFF {
			return total, fmt.Errorf("ciphertext too large: %d", len(ciphertext))
		}

		if err := writeUint16(c.conn, uint16(len(ciphertext))); err != nil {
			return total, err
		}
		if err := writeAll(c.conn, ciphertext); err != nil {
			return total, err
		}

		total += len(chunk)
	}

	return total, nil
}

// Close 关闭底层 TCP 连接。
func (c *noiseConn) Close() error {
	return c.conn.Close()
}

// LocalAddr 返回本地地址。
func (c *noiseConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr 返回远端地址。
func (c *noiseConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline 设置读写超时。
func (c *noiseConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline 设置读超时。
func (c *noiseConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline 设置写超时。
func (c *noiseConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// readPayloadFrame 读取一个完整 Noise 数据帧并解密为明文负载。
func (c *noiseConn) readPayloadFrame() ([]byte, error) {
	cipherLen, err := readUint16(c.conn)
	if err != nil {
		return nil, err
	}
	if cipherLen == 0 {
		return nil, errors.New("invalid noise frame: ciphertext length is 0")
	}

	ciphertext := make([]byte, cipherLen)
	if _, err := io.ReadFull(c.conn, ciphertext); err != nil {
		return nil, fmt.Errorf("read ciphertext failed: %w", err)
	}

	plaintext, err := c.recvCipher.Decrypt(nil, nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("noise decrypt failed: %w", err)
	}
	if len(plaintext) < noiseFrameLengthBytes {
		return nil, fmt.Errorf("invalid plaintext size: %d", len(plaintext))
	}

	plainLen := int(binary.BigEndian.Uint16(plaintext[:noiseFrameLengthBytes]))
	if plainLen > len(plaintext)-noiseFrameLengthBytes {
		return nil, fmt.Errorf("invalid plaintext length prefix: %d > %d", plainLen, len(plaintext)-noiseFrameLengthBytes)
	}

	out := make([]byte, plainLen)
	copy(out, plaintext[noiseFrameLengthBytes:noiseFrameLengthBytes+plainLen])
	return out, nil
}

// dialNoiseConn 建立 TCP 连接并完成 Noise 握手，返回可直接读写明文的连接。
func dialNoiseConn(addr string, privateKeyPath string, serverPublicKeyPath string, protocol noiseProtocolConfig, timeout time.Duration) (*noiseConn, error) {
	var clientStaticKey noise.DHKey
	var serverPublicKey []byte
	var err error

	if protocol.NeedsLocalStatic {
		var privateKey []byte

		privateKey, err = loadClientPrivateKey(privateKeyPath, protocol.KeySize)
		if err != nil {
			return nil, err
		}

		clientStaticKey, err = buildClientStaticKeypair(privateKey, protocol)
		if err != nil {
			return nil, err
		}
	}

	if protocol.NeedsRemoteStatic {
		serverPublicKey, err = loadServerPublicKey(serverPublicKeyPath, protocol.KeySize)
		if err != nil {
			return nil, err
		}
	}

	prologue, err := buildNoisePrologue(protocol)
	if err != nil {
		return nil, err
	}

	handshakeState, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   protocol.CipherSuite,
		Pattern:       protocol.Pattern,
		Initiator:     true,
		StaticKeypair: clientStaticKey,
		PeerStatic:    serverPublicKey,
		Prologue:      prologue,
	})
	if err != nil {
		return nil, fmt.Errorf("create handshake state failed: %w", err)
	}

	rawConn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", addr, err)
	}

	if err := rawConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("set handshake deadline failed: %w", err)
	}

	sendCipher, recvCipher, err := performNoiseHandshake(rawConn, handshakeState, protocol.Header)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	if err := rawConn.SetDeadline(time.Time{}); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("clear deadline failed: %w", err)
	}

	return &noiseConn{
		conn:       rawConn,
		sendCipher: sendCipher,
		recvCipher: recvCipher,
	}, nil
}

// performNoiseHandshake 按 initiator 发送/接收交替推进握手，直到产出双向 CipherState。
func performNoiseHandshake(conn net.Conn, state *noise.HandshakeState, header protocolHeader) (*noise.CipherState, *noise.CipherState, error) {
	firstNegotiationData := buildFirstNegotiationData(header)
	firstNegotiationSent := false

	for round := 1; ; round++ {
		handshakeMsg, sendCipher, recvCipher, err := state.WriteMessage(nil, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("write handshake message #%d failed: %w", round*2-1, err)
		}

		negotiationData := []byte(nil)
		if !firstNegotiationSent {
			negotiationData = firstNegotiationData
			firstNegotiationSent = true
		}

		if err := writeHandshakeFrame(conn, negotiationData, handshakeMsg); err != nil {
			return nil, nil, fmt.Errorf("send handshake message #%d failed: %w", round*2-1, err)
		}

		if sendCipher != nil || recvCipher != nil {
			if sendCipher == nil || recvCipher == nil {
				return nil, nil, errors.New("handshake finished but cipher states are nil")
			}
			return sendCipher, recvCipher, nil
		}

		responseNegotiationData, responseHandshakeMsg, err := readHandshakeFrame(conn)
		if err != nil {
			return nil, nil, fmt.Errorf("read handshake message #%d failed: %w", round*2, err)
		}
		if err := validateHandshakeNegotiationData(responseNegotiationData, header); err != nil {
			return nil, nil, err
		}

		_, sendCipher, recvCipher, err = state.ReadMessage(nil, responseHandshakeMsg)
		if err != nil {
			return nil, nil, fmt.Errorf("read handshake payload #%d failed: %w", round*2, err)
		}

		if sendCipher != nil || recvCipher != nil {
			if sendCipher == nil || recvCipher == nil {
				return nil, nil, errors.New("handshake finished but cipher states are nil")
			}
			return sendCipher, recvCipher, nil
		}
	}
}

// doHTTPGetOverNoise 使用 Noise 连接发送一个 HTTP GET 请求并返回响应。
func doHTTPGetOverNoise(addr string, privateKeyPath string, serverPublicKeyPath string, host string, path string, protocol noiseProtocolConfig, timeout time.Duration) (string, []byte, error) {
	conn, err := dialNoiseConn(addr, privateKeyPath, serverPublicKeyPath, protocol, timeout)
	if err != nil {
		return "", nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", nil, fmt.Errorf("set request deadline failed: %w", err)
	}

	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	if err := writeAll(conn, []byte(request)); err != nil {
		return "", nil, fmt.Errorf("write request failed: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		return "", nil, fmt.Errorf("read response failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("read response body failed: %w", err)
	}

	return resp.Status, body, nil
}

// doWebSocketEchoOverNoise 在 Noise 连接上完成 WS 升级、发送文本并读取回显。
func doWebSocketEchoOverNoise(addr string, privateKeyPath string, serverPublicKeyPath string, host string, path string, message string, protocol noiseProtocolConfig, timeout time.Duration) (string, string, error) {
	conn, err := dialNoiseConn(addr, privateKeyPath, serverPublicKeyPath, protocol, timeout)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", "", fmt.Errorf("set websocket deadline failed: %w", err)
	}

	clientKey, err := generateWebSocketKey()
	if err != nil {
		return "", "", err
	}

	request := strings.Builder{}
	request.WriteString(fmt.Sprintf("GET %s HTTP/1.1\r\n", path))
	request.WriteString(fmt.Sprintf("Host: %s\r\n", host))
	request.WriteString("Upgrade: websocket\r\n")
	request.WriteString("Connection: Upgrade\r\n")
	request.WriteString("Sec-WebSocket-Version: 13\r\n")
	request.WriteString(fmt.Sprintf("Sec-WebSocket-Key: %s\r\n", clientKey))
	request.WriteString("\r\n")

	if err := writeAll(conn, []byte(request.String())); err != nil {
		return "", "", fmt.Errorf("write websocket upgrade request failed: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		return "", "", fmt.Errorf("read websocket upgrade response failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return resp.Status, "", fmt.Errorf("websocket upgrade failed: %s", resp.Status)
	}

	accept := resp.Header.Get("Sec-WebSocket-Accept")
	expectedAccept := buildExpectedWebSocketAccept(clientKey)
	if accept != expectedAccept {
		return resp.Status, "", fmt.Errorf("invalid websocket accept header: got %q want %q", accept, expectedAccept)
	}

	if err := writeWebSocketFrame(conn, 0x1, []byte(message)); err != nil {
		return resp.Status, "", fmt.Errorf("write websocket message failed: %w", err)
	}

	for {
		opcode, payload, err := readWebSocketFrame(reader)
		if err != nil {
			return resp.Status, "", fmt.Errorf("read websocket frame failed: %w", err)
		}

		switch opcode {
		case 0x1, 0x2:
			return resp.Status, string(payload), nil
		case 0x8:
			return resp.Status, "", errors.New("websocket closed by server")
		case 0x9:
			if err := writeWebSocketFrame(conn, 0xA, payload); err != nil {
				return resp.Status, "", fmt.Errorf("write pong failed: %w", err)
			}
		default:
			continue
		}
	}
}

// loadClientPrivateKey 从文件加载客户端私钥，并校验长度与当前 DH 一致。
func loadClientPrivateKey(path string, keySize int) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key file failed: %w", err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("invalid private key size: got %d want %d", len(key), keySize)
	}
	return key, nil
}

// loadServerPublicKey 从文件加载服务端公钥，并按 nginx noise 模块的规则做 base64 解码。
func loadServerPublicKey(path string, keySize int) ([]byte, error) {
	keyText, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read server public key file failed: %w", err)
	}

	normalized := strings.NewReplacer("\n", "", "\r", "", "\t", "", " ", "").Replace(string(keyText))
	key, err := base64.StdEncoding.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("decode server public key failed: %w", err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("invalid server public key size: got %d want %d", len(key), keySize)
	}

	return key, nil
}

// parseNoiseProtocolConfig 解析协议名和 prologue，并构造客户端握手配置。
func parseNoiseProtocolConfig(name string, prologue string) (noiseProtocolConfig, error) {
	parts := strings.Split(name, "_")
	if len(parts) != 5 {
		return noiseProtocolConfig{}, fmt.Errorf("invalid noise protocol format: %s", name)
	}
	if parts[0] != "Noise" {
		return noiseProtocolConfig{}, fmt.Errorf("unsupported noise prefix: %s", parts[0])
	}

	patternSpec, err := parseNoisePattern(parts[1])
	if err != nil {
		return noiseProtocolConfig{}, err
	}
	dhID, dhName, keySize, dhFunc, err := parseNoiseDH(parts[2])
	if err != nil {
		return noiseProtocolConfig{}, err
	}
	cipherID, cipherFunc, err := parseNoiseCipher(parts[3])
	if err != nil {
		return noiseProtocolConfig{}, err
	}
	hashID, hashFunc, err := parseNoiseHash(parts[4])
	if err != nil {
		return noiseProtocolConfig{}, err
	}

	return noiseProtocolConfig{
		Name:     name,
		Prologue: prologue,
		DHName:   dhName,
		Header: protocolHeader{
			VersionID: noiseVersionID,
			DHID:      dhID,
			CipherID:  cipherID,
			HashID:    hashID,
			PatternID: patternSpec.ID,
		},
		KeySize:           keySize,
		CipherSuite:       noise.NewCipherSuite(dhFunc, cipherFunc, hashFunc),
		Pattern:           patternSpec.Pattern,
		NeedsLocalStatic:  patternSpec.NeedsLocalStatic,
		NeedsRemoteStatic: patternSpec.NeedsRemoteStatic,
	}, nil
}

// parseNoisePattern 解析并校验当前客户端支持的基础握手模式。
func parseNoisePattern(pattern string) (noisePatternSpec, error) {
	switch pattern {
	case "N":
		return noisePatternSpec{ID: 1, Pattern: noise.HandshakeN, NeedsRemoteStatic: true}, nil
	case "X":
		return noisePatternSpec{ID: 2, Pattern: noise.HandshakeX, NeedsLocalStatic: true, NeedsRemoteStatic: true}, nil
	case "K":
		return noisePatternSpec{ID: 3, Pattern: noise.HandshakeK, NeedsLocalStatic: true, NeedsRemoteStatic: true}, nil
	case "NN":
		return noisePatternSpec{ID: 4, Pattern: noise.HandshakeNN}, nil
	case "NK":
		return noisePatternSpec{ID: 5, Pattern: noise.HandshakeNK, NeedsRemoteStatic: true}, nil
	case "NX":
		return noisePatternSpec{ID: 6, Pattern: noise.HandshakeNX}, nil
	case "XN":
		return noisePatternSpec{ID: 7, Pattern: noise.HandshakeXN, NeedsLocalStatic: true}, nil
	case "XK":
		return noisePatternSpec{ID: 8, Pattern: noise.HandshakeXK, NeedsLocalStatic: true, NeedsRemoteStatic: true}, nil
	case "XX":
		return noisePatternSpec{ID: 9, Pattern: noise.HandshakeXX, NeedsLocalStatic: true}, nil
	case "KN":
		return noisePatternSpec{ID: 10, Pattern: noise.HandshakeKN, NeedsLocalStatic: true}, nil
	case "KK":
		return noisePatternSpec{ID: 11, Pattern: noise.HandshakeKK, NeedsLocalStatic: true, NeedsRemoteStatic: true}, nil
	case "KX":
		return noisePatternSpec{ID: 12, Pattern: noise.HandshakeKX, NeedsLocalStatic: true}, nil
	case "IN":
		return noisePatternSpec{ID: 13, Pattern: noise.HandshakeIN, NeedsLocalStatic: true}, nil
	case "IK":
		return noisePatternSpec{ID: 14, Pattern: noise.HandshakeIK, NeedsLocalStatic: true, NeedsRemoteStatic: true}, nil
	case "IX":
		return noisePatternSpec{ID: 15, Pattern: noise.HandshakeIX, NeedsLocalStatic: true}, nil
	default:
		return noisePatternSpec{}, fmt.Errorf("unsupported noise pattern for demo client: %s", pattern)
	}
}

// parseNoiseDH 解析并校验当前客户端支持的 DH 算法。
func parseNoiseDH(dh string) (byte, string, int, noise.DHFunc, error) {
	switch dh {
	case "25519":
		return 1, dh, 32, noise.DH25519, nil
	case "448":
		return 0, "", 0, nil, fmt.Errorf("unsupported noise dh for demo client: %s", dh)
	default:
		return 0, "", 0, nil, fmt.Errorf("unknown noise dh: %s", dh)
	}
}

// parseNoiseCipher 解析并校验当前客户端支持的对称算法。
func parseNoiseCipher(cipher string) (byte, noise.CipherFunc, error) {
	switch cipher {
	case "ChaChaPoly":
		return 1, noise.CipherChaChaPoly, nil
	case "AESGCM":
		return 2, noise.CipherAESGCM, nil
	default:
		return 0, nil, fmt.Errorf("unknown noise cipher: %s", cipher)
	}
}

// parseNoiseHash 解析并校验当前客户端支持的哈希算法。
func parseNoiseHash(hash string) (byte, noise.HashFunc, error) {
	switch hash {
	case "BLAKE2s":
		return 1, noise.HashBLAKE2s, nil
	case "BLAKE2b":
		return 2, noise.HashBLAKE2b, nil
	case "SHA256":
		return 3, noise.HashSHA256, nil
	case "SHA512":
		return 4, noise.HashSHA512, nil
	default:
		return 0, nil, fmt.Errorf("unknown noise hash: %s", hash)
	}
}

// buildClientStaticKeypair 基于当前 DH 私钥构造 Noise 静态密钥对。
func buildClientStaticKeypair(privateKey []byte, protocol noiseProtocolConfig) (noise.DHKey, error) {
	if protocol.DHName != "25519" {
		return noise.DHKey{}, fmt.Errorf("unsupported noise dh for static keypair: %s", protocol.DHName)
	}

	curve := ecdh.X25519()
	key, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("build x25519 private key failed: %w", err)
	}

	privateCopy := make([]byte, len(privateKey))
	copy(privateCopy, privateKey)

	return noise.DHKey{
		Private: privateCopy,
		Public:  key.PublicKey().Bytes(),
	}, nil
}

// validateNoiseKeyInputs 按当前握手模式校验静态密钥参数是否齐备。
func validateNoiseKeyInputs(protocol noiseProtocolConfig, privateKeyPath string, serverPublicKeyPath string) error {
	if protocol.NeedsLocalStatic && privateKeyPath == "" {
		return errors.New("current noise pattern requires -key")
	}
	if protocol.NeedsRemoteStatic && serverPublicKeyPath == "" {
		return errors.New("current noise pattern requires -server-public-key")
	}
	return nil
}

// buildNoisePrologue 构造与 nginx noise 模块一致的动态 prologue。
func buildNoisePrologue(protocol noiseProtocolConfig) ([]byte, error) {
	prologue := make([]byte, 0, len(protocol.Prologue)+2+noiseNegotiationLen)
	prologue = append(prologue, []byte(protocol.Prologue)...)

	negLen := make([]byte, 2)
	binary.BigEndian.PutUint16(negLen, noiseNegotiationLen)
	prologue = append(prologue, negLen...)

	prologue = append(prologue, buildFirstNegotiationData(protocol.Header)...)
	return prologue, nil
}

// buildFirstNegotiationData 构造首个协商头（version/dh/cipher/hash/pattern）。
func buildFirstNegotiationData(header protocolHeader) []byte {
	out := make([]byte, noiseNegotiationLen)
	binary.BigEndian.PutUint16(out[:2], header.VersionID)
	out[2] = header.DHID
	out[3] = header.CipherID
	out[4] = header.HashID
	out[5] = header.PatternID
	return out
}

// validateHandshakeNegotiationData 校验服务端握手响应携带的协商数据。
func validateHandshakeNegotiationData(data []byte, header protocolHeader) error {
	if len(data) == 0 {
		return nil
	}

	if len(data) != 3 {
		return fmt.Errorf("unexpected handshake negotiation data length: %d", len(data))
	}

	version := binary.BigEndian.Uint16(data[:2])
	status := data[2]

	if version != header.VersionID {
		return fmt.Errorf("unexpected handshake version: %d", version)
	}

	switch status {
	case 0x00:
		return nil
	case 0x01:
		return errors.New("server returned fallback status (0x01), unsupported")
	case 0xFF:
		return errors.New("server returned error status (0xFF)")
	default:
		return fmt.Errorf("unexpected handshake status: 0x%02X", status)
	}
}

// writeHandshakeFrame 按 nginx noise 握手格式写入一条消息。
func writeHandshakeFrame(w io.Writer, negotiationData []byte, noiseMessage []byte) error {
	if len(negotiationData) > 0xFFFF {
		return fmt.Errorf("negotiation data too large: %d", len(negotiationData))
	}
	if len(noiseMessage) > 0xFFFF {
		return fmt.Errorf("noise handshake message too large: %d", len(noiseMessage))
	}

	if err := writeUint16(w, uint16(len(negotiationData))); err != nil {
		return err
	}
	if err := writeAll(w, negotiationData); err != nil {
		return err
	}
	if err := writeUint16(w, uint16(len(noiseMessage))); err != nil {
		return err
	}
	return writeAll(w, noiseMessage)
}

// readHandshakeFrame 按 nginx noise 握手格式读取一条消息。
func readHandshakeFrame(r io.Reader) ([]byte, []byte, error) {
	negLen, err := readUint16(r)
	if err != nil {
		return nil, nil, err
	}

	negotiationData := make([]byte, negLen)
	if _, err := io.ReadFull(r, negotiationData); err != nil {
		return nil, nil, fmt.Errorf("read negotiation data failed: %w", err)
	}

	msgLen, err := readUint16(r)
	if err != nil {
		return nil, nil, err
	}

	noiseMessage := make([]byte, msgLen)
	if _, err := io.ReadFull(r, noiseMessage); err != nil {
		return nil, nil, fmt.Errorf("read handshake message failed: %w", err)
	}

	return negotiationData, noiseMessage, nil
}

// generateWebSocketKey 生成 websocket 升级请求使用的随机 key。
func generateWebSocketKey() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate websocket key failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// buildExpectedWebSocketAccept 计算服务端应返回的 Sec-WebSocket-Accept。
func buildExpectedWebSocketAccept(clientKey string) string {
	sum := sha1.Sum([]byte(clientKey + websocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// writeWebSocketFrame 发送客户端 websocket 帧（客户端发送必须带 mask）。
func writeWebSocketFrame(w io.Writer, opcode byte, payload []byte) error {
	frame := make([]byte, 0, 16+len(payload))
	frame = append(frame, 0x80|(opcode&0x0F))

	payloadLen := len(payload)
	switch {
	case payloadLen <= 125:
		frame = append(frame, 0x80|byte(payloadLen))
	case payloadLen <= 0xFFFF:
		frame = append(frame, 0x80|126)
		tmp := make([]byte, 2)
		binary.BigEndian.PutUint16(tmp, uint16(payloadLen))
		frame = append(frame, tmp...)
	default:
		frame = append(frame, 0x80|127)
		tmp := make([]byte, 8)
		binary.BigEndian.PutUint64(tmp, uint64(payloadLen))
		frame = append(frame, tmp...)
	}

	maskKey := make([]byte, 4)
	if _, err := rand.Read(maskKey); err != nil {
		return fmt.Errorf("generate websocket mask key failed: %w", err)
	}
	frame = append(frame, maskKey...)

	masked := make([]byte, payloadLen)
	for i := 0; i < payloadLen; i++ {
		masked[i] = payload[i] ^ maskKey[i%4]
	}
	frame = append(frame, masked...)

	return writeAll(w, frame)
}

// readWebSocketFrame 读取并解析一帧 websocket 数据。
func readWebSocketFrame(r io.Reader) (byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}

	fin := (header[0] & 0x80) != 0
	opcode := header[0] & 0x0F
	masked := (header[1] & 0x80) != 0
	payloadLenMarker := header[1] & 0x7F

	var payloadLen uint64
	switch payloadLenMarker {
	case 126:
		tmp := make([]byte, 2)
		if _, err := io.ReadFull(r, tmp); err != nil {
			return 0, nil, err
		}
		payloadLen = uint64(binary.BigEndian.Uint16(tmp))
	case 127:
		tmp := make([]byte, 8)
		if _, err := io.ReadFull(r, tmp); err != nil {
			return 0, nil, err
		}
		payloadLen = binary.BigEndian.Uint64(tmp)
	default:
		payloadLen = uint64(payloadLenMarker)
	}

	if payloadLen > 1<<20 {
		return 0, nil, fmt.Errorf("websocket payload too large: %d", payloadLen)
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(r, maskKey); err != nil {
			return 0, nil, err
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	if !fin {
		return 0, nil, errors.New("fragmented websocket frame is not supported in this demo client")
	}

	return opcode, payload, nil
}

// writeUint16 以网络字节序写入 uint16。
func writeUint16(w io.Writer, v uint16) error {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return writeAll(w, buf)
}

// readUint16 以网络字节序读取 uint16。
func readUint16(r io.Reader) (uint16, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf), nil
}

// writeAll 确保将数据完整写出。
func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// formatBodyPreview 输出 body 的预览文本，避免日志过长。
func formatBodyPreview(body []byte) string {
	const max = 256
	if len(body) == 0 {
		return "<empty>"
	}

	text := string(body)
	if len(text) > max {
		return text[:max] + "...(truncated)"
	}
	return text
}

func main() {
	defaultKeyPath := "/root/ponny/nginx-1.16.1/virgil-nginx-noise-socket/example/client_key_25519"

	addr := flag.String("addr", "127.0.0.1:4430", "noise socket 服务地址")
	host := flag.String("host", "localhost", "HTTP/WS Host 头")
	privateKeyPath := flag.String("key", defaultKeyPath, "客户端私钥文件路径")
	serverPublicKeyPath := flag.String("server-public-key", "", "服务端公钥文件路径，仅在握手模式需要预置 responder 静态公钥时必填")
	noiseProtocol := flag.String("noise-protocol", defaultNoiseProtocol, "Noise 协议名，例如 Noise_XX_25519_AESGCM_BLAKE2b")
	noisePrologue := flag.String("noise-prologue", defaultNoisePrologue, "Noise prologue 文本")
	timeout := flag.Duration("timeout", 15*time.Second, "每个请求超时时间")
	wsMessage := flag.String("ws-message", "hello over noise", "发送到 /ws/echo 的文本消息")
	flag.Parse()

	protocol, err := parseNoiseProtocolConfig(*noiseProtocol, *noisePrologue)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析 Noise 配置失败: %v\n", err)
		os.Exit(1)
	}
	if err := validateNoiseKeyInputs(protocol, *privateKeyPath, *serverPublicKeyPath); err != nil {
		fmt.Fprintf(os.Stderr, "校验 Noise 密钥参数失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("目标 Noise 服务: %s\n", *addr)
	fmt.Printf("Noise 协议: %s\n", protocol.Name)
	fmt.Printf("Noise prologue: %q\n", protocol.Prologue)
	if protocol.NeedsLocalStatic {
		fmt.Printf("客户端私钥: %s\n", *privateKeyPath)
	}
	if protocol.NeedsRemoteStatic {
		fmt.Printf("服务端公钥: %s\n", *serverPublicKeyPath)
	}
	fmt.Println("开始请求 /api/echo ...")

	apiStatus, apiBody, err := doHTTPGetOverNoise(*addr, *privateKeyPath, *serverPublicKeyPath, *host, "/api/echo", protocol, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "请求 /api/echo 失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[/api/echo] status=%s body=%s\n", apiStatus, formatBodyPreview(apiBody))

	fmt.Println("开始请求 /ws/echo ...")
	wsStatus, wsReply, err := doWebSocketEchoOverNoise(*addr, *privateKeyPath, *serverPublicKeyPath, *host, "/ws/echo", *wsMessage, protocol, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "请求 /ws/echo 失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[/ws/echo] status=%s send=%q recv=%q\n", wsStatus, *wsMessage, wsReply)

	fmt.Println("开始请求 /download/dl ...")
	downloadStatus, downloadBody, err := doHTTPGetOverNoise(*addr, *privateKeyPath, *serverPublicKeyPath, *host, "/download/dl", protocol, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "请求 /download/dl 失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[/download/dl] status=%s bytes=%d preview=%s\n", downloadStatus, len(downloadBody), formatBodyPreview(downloadBody))
}
