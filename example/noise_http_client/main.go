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
	defaultNoiseProtocol    = "Noise_NK_25519_AESGCM_SHA256"
	defaultNoisePrologue    = "NoiseSocketInit1"
	noiseNegotiationLen     = 6
	noiseVersionID          = 1
	noiseDHCurve25519ID     = 1
	noiseCipherChaChaPolyID = 1
	noiseCipherAESGCMID     = 2
	noiseHashBLAKE2sID      = 1
	noiseHashBLAKE2bID      = 2
	noiseHashSHA256ID       = 3
	noiseHashSHA512ID       = 4
	noisePatternNNID        = 4
	noisePatternNKID        = 5
	noisePatternNXID        = 6
	noisePatternXNID        = 7
	noisePatternXKID        = 8
	noisePatternXXID        = 9
	noisePatternKNID        = 10
	noisePatternKKID        = 11
	noisePatternKXID        = 12
	noisePatternINID        = 13
	noisePatternIKID        = 14
	noisePatternIXID        = 15
	noiseFrameLengthBytes   = 2
	noiseKeySize            = 32
	maxPlainFrameSize       = 65517

	noiseHandshakeStatusOK                     = 0x00
	noiseHandshakeStatusVersionMismatch        = 0x01
	noiseHandshakeStatusNegotiationMismatch    = 0x02
	noiseHandshakeStatusMalformedNegotiation   = 0x03
	noiseHandshakeStatusMalformedHandshake     = 0x04
	noiseHandshakeStatusPeerVerificationFailed = 0x05
	noiseHandshakeStatusInternalError          = 0x06

	websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

type protocolHeader struct {
	VersionID uint16
	DHID      byte
	CipherID  byte
	HashID    byte
	PatternID byte
}

type noiseProtocolSpec struct {
	Name                  string
	Header                protocolHeader
	Pattern               noise.HandshakePattern
	Cipher                noise.CipherFunc
	Hash                  noise.HashFunc
	NeedsClientPrivateKey bool
	NeedsServerPublicKey  bool
}

type noiseHandshakeConfig struct {
	Protocol      noiseProtocolSpec
	PrologueText  string
	ClientPrivKey []byte
	ServerPubKey  []byte
}

var interactivePatterns = map[string]struct {
	id                    byte
	pattern               noise.HandshakePattern
	needsClientPrivateKey bool
	needsServerPublicKey  bool
}{
	"NN": {id: noisePatternNNID, pattern: noise.HandshakeNN},
	"KN": {id: noisePatternKNID, pattern: noise.HandshakeKN, needsClientPrivateKey: true},
	"NK": {id: noisePatternNKID, pattern: noise.HandshakeNK, needsServerPublicKey: true},
	"KK": {id: noisePatternKKID, pattern: noise.HandshakeKK, needsClientPrivateKey: true, needsServerPublicKey: true},
	"NX": {id: noisePatternNXID, pattern: noise.HandshakeNX},
	"KX": {id: noisePatternKXID, pattern: noise.HandshakeKX, needsClientPrivateKey: true},
	"XN": {id: noisePatternXNID, pattern: noise.HandshakeXN, needsClientPrivateKey: true},
	"IN": {id: noisePatternINID, pattern: noise.HandshakeIN, needsClientPrivateKey: true},
	"XK": {id: noisePatternXKID, pattern: noise.HandshakeXK, needsClientPrivateKey: true, needsServerPublicKey: true},
	"IK": {id: noisePatternIKID, pattern: noise.HandshakeIK, needsClientPrivateKey: true, needsServerPublicKey: true},
	"XX": {id: noisePatternXXID, pattern: noise.HandshakeXX, needsClientPrivateKey: true},
	"IX": {id: noisePatternIXID, pattern: noise.HandshakeIX, needsClientPrivateKey: true},
}

type noiseConn struct {
	conn       net.Conn
	sendCipher *noise.CipherState
	recvCipher *noise.CipherState

	readMu  sync.Mutex
	writeMu sync.Mutex
	readBuf []byte
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

// parseNoiseProtocol 解析形如 Noise_NK_25519_AESGCM_SHA256 的协议串。
func parseNoiseProtocol(protocol string) (noiseProtocolSpec, error) {
	parts := strings.Split(protocol, "_")
	if len(parts) != 5 || parts[0] != "Noise" {
		return noiseProtocolSpec{}, fmt.Errorf("invalid noise protocol: %s", protocol)
	}

	if parts[2] != "25519" {
		return noiseProtocolSpec{}, fmt.Errorf("unsupported dh: %s", parts[2])
	}

	patternSpec, ok := interactivePatterns[parts[1]]
	if !ok {
		return noiseProtocolSpec{}, fmt.Errorf("unsupported handshake pattern: %s", parts[1])
	}

	spec := noiseProtocolSpec{
		Name: protocol,
		Header: protocolHeader{
			VersionID: noiseVersionID,
			DHID:      noiseDHCurve25519ID,
			PatternID: patternSpec.id,
		},
		Pattern:               patternSpec.pattern,
		NeedsClientPrivateKey: patternSpec.needsClientPrivateKey,
		NeedsServerPublicKey:  patternSpec.needsServerPublicKey,
	}

	switch parts[3] {
	case "AESGCM":
		spec.Header.CipherID = noiseCipherAESGCMID
		spec.Cipher = noise.CipherAESGCM
	case "ChaChaPoly":
		spec.Header.CipherID = noiseCipherChaChaPolyID
		spec.Cipher = noise.CipherChaChaPoly
	default:
		return noiseProtocolSpec{}, fmt.Errorf("unsupported cipher: %s", parts[3])
	}

	switch parts[4] {
	case "SHA256":
		spec.Header.HashID = noiseHashSHA256ID
		spec.Hash = noise.HashSHA256
	case "SHA512":
		spec.Header.HashID = noiseHashSHA512ID
		spec.Hash = noise.HashSHA512
	case "BLAKE2b":
		spec.Header.HashID = noiseHashBLAKE2bID
		spec.Hash = noise.HashBLAKE2b
	case "BLAKE2s":
		spec.Header.HashID = noiseHashBLAKE2sID
		spec.Hash = noise.HashBLAKE2s
	default:
		return noiseProtocolSpec{}, fmt.Errorf("unsupported hash: %s", parts[4])
	}

	return spec, nil
}

// buildInitiatorHandshakeConfig 构造发起方的握手配置。
func buildInitiatorHandshakeConfig(spec noiseProtocolSpec, prologueText string, clientPrivateKey []byte, serverPublicKey []byte) (noise.Config, error) {
	if spec.NeedsClientPrivateKey && len(clientPrivateKey) != noiseKeySize {
		return noise.Config{}, fmt.Errorf("invalid client private key size: got %d want %d", len(clientPrivateKey), noiseKeySize)
	}
	if spec.NeedsServerPublicKey && len(serverPublicKey) != noiseKeySize {
		return noise.Config{}, fmt.Errorf("invalid server public key size: got %d want %d", len(serverPublicKey), noiseKeySize)
	}

	prologue, err := buildNoisePrologue(prologueText, spec.Header)
	if err != nil {
		return noise.Config{}, err
	}

	var clientStaticKeypair noise.DHKey
	if len(clientPrivateKey) != 0 {
		clientStaticKeypair, err = buildX25519Keypair(clientPrivateKey)
		if err != nil {
			return noise.Config{}, err
		}
	}

	var serverPublicKeyCopy []byte
	if len(serverPublicKey) != 0 {
		serverPublicKeyCopy = make([]byte, len(serverPublicKey))
		copy(serverPublicKeyCopy, serverPublicKey)
	}

	return noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, spec.Cipher, spec.Hash),
		Pattern:       spec.Pattern,
		Initiator:     true,
		StaticKeypair: clientStaticKeypair,
		PeerStatic:    serverPublicKeyCopy,
		Prologue:      prologue,
	}, nil
}

// dialNoiseConn 建立 TCP 连接并完成 initiator 侧 Noise 握手，返回可直接读写明文的连接。
func dialNoiseConn(addr string, config noiseHandshakeConfig, timeout time.Duration) (*noiseConn, error) {
	handshakeConfig, err := buildInitiatorHandshakeConfig(
		config.Protocol,
		config.PrologueText,
		config.ClientPrivKey,
		config.ServerPubKey,
	)
	if err != nil {
		return nil, err
	}

	handshakeState, err := noise.NewHandshakeState(handshakeConfig)
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

	sendCipher, recvCipher, err := performNoiseHandshake(rawConn, handshakeState, config.Protocol.Header)
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

// performNoiseHandshake 执行 initiator 侧握手消息交换，并产出双向 CipherState。
func performNoiseHandshake(conn net.Conn, state *noise.HandshakeState, header protocolHeader) (*noise.CipherState, *noise.CipherState, error) {
	handshakeMsg, sendCipher, recvCipher, err := state.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("write handshake message #1 failed: %w", err)
	}

	firstNegotiationData := buildFirstNegotiationData(header)
	if err := writeHandshakeFrame(conn, firstNegotiationData, handshakeMsg); err != nil {
		return nil, nil, fmt.Errorf("send handshake message #1 failed: %w", err)
	}
	if sendCipher != nil && recvCipher != nil {
		return sendCipher, recvCipher, nil
	}

	for handshakeMsgNum := 2; ; handshakeMsgNum++ {
		negotiationData, nextHandshakeMsg, err := readHandshakeFrame(conn)
		if err != nil {
			return nil, nil, fmt.Errorf("read handshake message #%d failed: %w", handshakeMsgNum, err)
		}
		if err := validateSecondNegotiationData(negotiationData); err != nil {
			return nil, nil, err
		}

		_, sendCipher, recvCipher, err = state.ReadMessage(nil, nextHandshakeMsg)
		if err != nil {
			return nil, nil, fmt.Errorf("read handshake payload #%d failed: %w", handshakeMsgNum, err)
		}
		if sendCipher != nil && recvCipher != nil {
			return sendCipher, recvCipher, nil
		}

		handshakeMsgNum++
		handshakeMsg, sendCipher, recvCipher, err = state.WriteMessage(nil, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("write handshake message #%d failed: %w", handshakeMsgNum, err)
		}
		if err := writeHandshakeFrame(conn, nil, handshakeMsg); err != nil {
			return nil, nil, fmt.Errorf("send handshake message #%d failed: %w", handshakeMsgNum, err)
		}
		if sendCipher != nil && recvCipher != nil {
			return sendCipher, recvCipher, nil
		}
	}
}

// doHTTPGetOverNoise 使用 Noise 连接发送一个 HTTP GET 请求并返回响应。
func doHTTPGetOverNoise(addr string, handshakeConfig noiseHandshakeConfig, host string, path string, timeout time.Duration) (string, []byte, error) {
	conn, err := dialNoiseConn(addr, handshakeConfig, timeout)
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
func doWebSocketEchoOverNoise(addr string, handshakeConfig noiseHandshakeConfig, host string, path string, message string, timeout time.Duration) (string, string, error) {
	conn, err := dialNoiseConn(addr, handshakeConfig, timeout)
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

// loadRawX25519Key 从文件加载 32 字节原始 X25519 密钥。
func loadRawX25519Key(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file failed: %w", err)
	}
	if len(key) != noiseKeySize {
		return nil, fmt.Errorf("invalid key size: got %d want %d", len(key), noiseKeySize)
	}
	return key, nil
}

// deriveX25519PublicKey 基于 32 字节 X25519 私钥推导公钥。
func deriveX25519PublicKey(privateKey []byte) ([]byte, error) {
	curve := ecdh.X25519()
	key, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("build x25519 private key failed: %w", err)
	}

	publicKey := key.PublicKey().Bytes()
	publicKeyCopy := make([]byte, len(publicKey))
	copy(publicKeyCopy, publicKey)
	return publicKeyCopy, nil
}

// buildX25519Keypair 基于 32 字节 X25519 私钥构造 Noise 需要的完整 keypair。
func buildX25519Keypair(privateKey []byte) (noise.DHKey, error) {
	publicKey, err := deriveX25519PublicKey(privateKey)
	if err != nil {
		return noise.DHKey{}, err
	}

	privateKeyCopy := make([]byte, len(privateKey))
	copy(privateKeyCopy, privateKey)

	return noise.DHKey{
		Private: privateKeyCopy,
		Public:  publicKey,
	}, nil
}

// resolveClientPrivateKey 仅在模式需要 initiator static 时加载客户端私钥。
func resolveClientPrivateKey(privateKeyPath string, required bool) ([]byte, error) {
	if privateKeyPath == "" {
		if required {
			return nil, errors.New("client private key is required")
		}
		return nil, nil
	}

	return loadRawX25519Key(privateKeyPath)
}

// resolveServerPublicKey 仅在模式需要 responder static 时解析服务端静态公钥。
func resolveServerPublicKey(publicKeyPath string, demoPrivateKeyPath string, required bool) ([]byte, error) {
	if !required {
		return nil, nil
	}

	if publicKeyPath != "" {
		return loadRawX25519Key(publicKeyPath)
	}

	if demoPrivateKeyPath == "" {
		return nil, errors.New("server public key is required")
	}

	privateKey, err := loadRawX25519Key(demoPrivateKeyPath)
	if err != nil {
		return nil, err
	}
	return deriveX25519PublicKey(privateKey)
}

// buildNoisePrologue 构造与 nginx noise 模块一致的 prologue。
func buildNoisePrologue(prologueText string, header protocolHeader) ([]byte, error) {
	prologue := make([]byte, 0, len(prologueText)+2+noiseNegotiationLen)
	prologue = append(prologue, []byte(prologueText)...)

	negLen := make([]byte, 2)
	binary.BigEndian.PutUint16(negLen, noiseNegotiationLen)
	prologue = append(prologue, negLen...)

	prologue = append(prologue, buildFirstNegotiationData(header)...)
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

// validateSecondNegotiationData 校验服务端第二条握手消息协商数据。
func validateSecondNegotiationData(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	if len(data) != 3 {
		return fmt.Errorf("malformed handshake negotiation: unexpected data length %d", len(data))
	}

	version := binary.BigEndian.Uint16(data[:2])
	status := data[2]

	if version != noiseVersionID {
		return fmt.Errorf("malformed handshake negotiation: unexpected version %d", version)
	}

	switch status {
	case noiseHandshakeStatusOK:
		return errors.New("malformed handshake negotiation: unexpected OK status frame")
	case noiseHandshakeStatusVersionMismatch:
		return errors.New("server rejected handshake: VERSION_MISMATCH")
	case noiseHandshakeStatusNegotiationMismatch:
		return errors.New("server rejected handshake: NEGOTIATION_MISMATCH")
	case noiseHandshakeStatusMalformedNegotiation:
		return errors.New("server rejected handshake: MALFORMED_NEGOTIATION")
	case noiseHandshakeStatusMalformedHandshake:
		return errors.New("server rejected handshake: MALFORMED_HANDSHAKE")
	case noiseHandshakeStatusPeerVerificationFailed:
		return errors.New("server rejected handshake: PEER_VERIFICATION_FAILED")
	case noiseHandshakeStatusInternalError:
		return errors.New("server rejected handshake: INTERNAL_ERROR")
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
	defaultServerPrivateKeyPath := "/root/ponny/nginx-1.16.1/virgil-nginx-noise-socket/example/server_key_25519"

	addr := flag.String("addr", "127.0.0.1:4430", "noise socket 服务地址")
	host := flag.String("host", "localhost", "HTTP/WS Host 头")
	protocolName := flag.String("protocol", defaultNoiseProtocol, "Noise 协议串，例如 Noise_NK_25519_AESGCM_SHA256")
	prologueText := flag.String("prologue", defaultNoisePrologue, "Noise prologue 文本")
	clientPrivateKeyPath := flag.String("client-priv", "", "客户端静态私钥文件路径（32字节二进制，仅在模式需要 initiator static 时使用）")
	serverPublicKeyPath := flag.String("server-pub", "", "服务端静态公钥文件路径（32字节二进制，仅在模式需要 responder static 预共享时使用）")
	serverDemoPrivateKeyPath := flag.String("server-private-demo", defaultServerPrivateKeyPath, "仅本地 demo 使用：当模式需要 responder static 预共享时，从服务端私钥推导静态公钥")
	timeout := flag.Duration("timeout", 15*time.Second, "每个请求超时时间")
	wsMessage := flag.String("ws-message", "hello over noise", "发送到 /ws/echo 的文本消息")
	flag.Parse()

	protocol, err := parseNoiseProtocol(*protocolName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析协议失败: %v\n", err)
		os.Exit(1)
	}

	clientPrivateKey, err := resolveClientPrivateKey(*clientPrivateKeyPath, protocol.NeedsClientPrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载客户端私钥失败: %v\n", err)
		os.Exit(1)
	}

	serverPublicKey, err := resolveServerPublicKey(
		*serverPublicKeyPath,
		*serverDemoPrivateKeyPath,
		protocol.NeedsServerPublicKey,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载服务端公钥失败: %v\n", err)
		os.Exit(1)
	}

	handshakeConfig := noiseHandshakeConfig{
		Protocol:      protocol,
		PrologueText:  *prologueText,
		ClientPrivKey: clientPrivateKey,
		ServerPubKey:  serverPublicKey,
	}

	fmt.Printf("目标 Noise 服务: %s\n", *addr)
	fmt.Printf("Noise 协议: %s\n", protocol.Name)
	fmt.Printf("Noise prologue: %s\n", *prologueText)
	fmt.Println("开始请求 /api/echo ...")

	apiStatus, apiBody, err := doHTTPGetOverNoise(*addr, handshakeConfig, *host, "/api/echo", *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "请求 /api/echo 失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[/api/echo] status=%s body=%s\n", apiStatus, formatBodyPreview(apiBody))

	fmt.Println("开始请求 /ws/echo ...")
	wsStatus, wsReply, err := doWebSocketEchoOverNoise(*addr, handshakeConfig, *host, "/ws/echo", *wsMessage, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "请求 /ws/echo 失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[/ws/echo] status=%s send=%q recv=%q\n", wsStatus, *wsMessage, wsReply)

	fmt.Println("开始请求 /download/dl ...")
	downloadStatus, downloadBody, err := doHTTPGetOverNoise(*addr, handshakeConfig, *host, "/download/dl", *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "请求 /download/dl 失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[/download/dl] status=%s bytes=%d preview=%s\n", downloadStatus, len(downloadBody), formatBodyPreview(downloadBody))
}
