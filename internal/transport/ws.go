package transport

// 最小 WebSocket 载体（RFC 6455 子集，零第三方依赖——M3，设计文档 §7）：
//   - 仅二进制帧（opcode 0x2），每帧完整消息、不分片
//   - 客户端发送必须掩码（RFC 强制），服务端发送不掩码
//   - 处理 ping/pong/close 控制帧
//   - SetDeadline 通过看门狗定时器关闭连接实现（诚实超时，而非 no-op）
//
// 设计定位：运维部署兼容性（可置于 nginx/CDN 之后），协议本体仍是自定义帧。

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
const maxWSMessage = 1 << 20 // 1MB，防御性上限（我们的帧最大 13+16KB）

var errWSClosed = errors.New("WebSocket 连接已关闭")

// ---- 服务端升级 ----

// serveWS 在 ln 上提供 HTTP 升级服务，升级成功后的连接交给 onConn。
func serveWS(ln net.Listener, onConn func(net.Conn)) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ghostpipe", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgradeWS(w, r)
		if err != nil {
			return
		}
		onConn(conn)
	})
	_ = http.Serve(ln, mux)
}

func upgradeWS(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		http.Error(w, "需要 WebSocket 升级", http.StatusBadRequest)
		return nil, errors.New("非 WebSocket 请求")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "缺少 Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, errors.New("缺少 Sec-WebSocket-Key")
	}
	h := w.Header()
	h.Set("Upgrade", "websocket")
	h.Set("Connection", "Upgrade")
	h.Set("Sec-WebSocket-Accept", wsAcceptKey(key))
	w.WriteHeader(http.StatusSwitchingProtocols)

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("连接不支持 Hijack")
	}
	nc, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	if err := brw.Writer.Flush(); err != nil { // 101 响应刷出缓冲
		nc.Close()
		return nil, err
	}
	return newWSConn(nc, brw.Reader, false), nil
}

func wsAcceptKey(key string) string {
	h := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec // RFC 6455 规定 SHA1，非安全用途
	return base64.StdEncoding.EncodeToString(h[:])
}

// ---- 客户端拨号 ----

func dialWS(raw net.Conn, addr, path string, timeout time.Duration) (net.Conn, error) {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil && h == "" {
		host = addr
	}
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := raw.Write([]byte(req)); err != nil {
		return nil, err
	}
	br := bufio.NewReader(raw)
	// 状态行
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(statusLine, "101") {
		return nil, fmt.Errorf("升级响应异常: %s", strings.TrimSpace(statusLine))
	}
	// 头部
	accept := ""
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if kv := strings.SplitN(line, ":", 2); len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "Sec-WebSocket-Accept") {
			accept = strings.TrimSpace(kv[1])
		}
	}
	if accept != wsAcceptKey(key) {
		return nil, errors.New("Sec-WebSocket-Accept 校验失败")
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return newWSConn(raw, br, true), nil
}

// ---- WS 连接（实现 net.Conn）----

type wsConn struct {
	nc     net.Conn
	br     *bufio.Reader
	client bool // 客户端发送必须掩码

	wmu   sync.Mutex
	rbuf  []byte
	dead  atomicFlag
	dmu   sync.Mutex
	timer *time.Timer
}

// atomicFlag 极简原子布尔
type atomicFlag struct {
	mu    sync.Mutex
	value bool
}

func (f *atomicFlag) set() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	old := f.value
	f.value = true
	return !old
}

func (f *atomicFlag) get() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.value
}

func newWSConn(nc net.Conn, br *bufio.Reader, client bool) *wsConn {
	return &wsConn{nc: nc, br: br, client: client}
}

func (c *wsConn) Read(p []byte) (int, error) {
	for {
		if len(c.rbuf) > 0 {
			n := copy(p, c.rbuf)
			c.rbuf = c.rbuf[n:]
			return n, nil
		}
		if c.dead.get() {
			return 0, errWSClosed
		}
		opcode, payload, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		switch opcode {
		case 0x2: // binary：我们的协议数据
			c.rbuf = payload
		case 0x8: // close
			_ = c.writeControl(0x8, nil)
			return 0, io.EOF
		case 0x9: // ping → pong
			_ = c.writeControl(0xA, payload)
		case 0xA: // pong → 忽略
		default: // 其他 opcode 忽略（含 text 0x1，防御性跳过）
		}
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	if c.dead.get() {
		return 0, errWSClosed
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.writeFrame(0x2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) Close() error {
	if c.dead.set() {
		_ = c.writeControl(0x8, nil) // best effort close 帧
	}
	return c.nc.Close()
}

func (c *wsConn) LocalAddr() net.Addr  { return c.nc.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr { return c.nc.RemoteAddr() }

// SetDeadline 看门狗实现：到点关闭连接，使阻塞中的 Read/Write 返回错误
func (c *wsConn) SetDeadline(t time.Time) error {
	c.setDeadline(t)
	return nil
}

func (c *wsConn) SetReadDeadline(t time.Time) error {
	c.setDeadline(t)
	return nil
}

func (c *wsConn) SetWriteDeadline(t time.Time) error {
	c.setDeadline(t)
	return nil
}

func (c *wsConn) setDeadline(t time.Time) {
	c.dmu.Lock()
	defer c.dmu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if t.IsZero() {
		return
	}
	d := time.Until(t)
	if d <= 0 {
		_ = c.Close()
		return
	}
	c.timer = time.AfterFunc(d, func() { _ = c.Close() })
}

// readFrame 读取一个完整 WS 帧
func (c *wsConn) readFrame() (byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return 0, nil, err
	}
	opcode := hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	l := uint64(hdr[1] & 0x7f)
	switch l {
	case 126:
		var e [2]byte
		if _, err := io.ReadFull(c.br, e[:]); err != nil {
			return 0, nil, err
		}
		l = uint64(binary.BigEndian.Uint16(e[:]))
	case 127:
		var e [8]byte
		if _, err := io.ReadFull(c.br, e[:]); err != nil {
			return 0, nil, err
		}
		l = binary.BigEndian.Uint64(e[:])
	}
	if l > maxWSMessage {
		return 0, nil, fmt.Errorf("WS 消息 %d 字节超过上限 %d", l, maxWSMessage)
	}
	var key [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, key[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, l)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= key[i%4]
		}
	}
	return opcode, payload, nil
}

func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	return c.writeRaw(opcode, payload, c.client)
}

func (c *wsConn) writeControl(opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.writeRaw(opcode, payload, c.client)
}

func (c *wsConn) writeRaw(opcode byte, payload []byte, mask bool) error {
	var hdr [14]byte // 最长：2 头 + 8 长度 + 4 掩码
	hdr[0] = 0x80 | opcode
	n := len(payload)
	idx := 2
	switch {
	case n < 126:
		hdr[1] = byte(n)
	case n <= 0xffff:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		idx = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		idx = 10
	}
	body := payload
	if mask {
		hdr[1] |= 0x80
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		copy(hdr[idx:idx+4], key[:])
		idx += 4
		masked := make([]byte, n)
		for i := range payload {
			masked[i] = payload[i] ^ key[i%4]
		}
		body = masked
	}
	if _, err := c.nc.Write(hdr[:idx]); err != nil {
		return err
	}
	if n > 0 {
		_, err := c.nc.Write(body)
		return err
	}
	return nil
}

// ---- 动态监听器：把升级后的 WS 连接按 net.Listener 语义交付 ----

type dynamicListener struct {
	ch      chan net.Conn
	closed  chan struct{}
	once    sync.Once
	addrMu  sync.Mutex
	addr    net.Addr
}

func newDynamicListener() *dynamicListener {
	return &dynamicListener{ch: make(chan net.Conn, 16), closed: make(chan struct{})}
}

func (l *dynamicListener) push(conn net.Conn) {
	l.addrMu.Lock()
	if l.addr == nil {
		l.addr = conn.LocalAddr()
	}
	l.addrMu.Unlock()
	select {
	case l.ch <- conn:
	case <-l.closed:
		conn.Close()
	}
}

func (l *dynamicListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, errors.New("监听器已关闭")
	}
}

func (l *dynamicListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *dynamicListener) Addr() net.Addr {
	l.addrMu.Lock()
	defer l.addrMu.Unlock()
	if l.addr != nil {
		return l.addr
	}
	return &net.TCPAddr{}
}
