// Package client 实现 ghostpipe 客户端（内网机器侧）。
//
// 职责：出网连接服务端、双向认证、注册隧道、（M2）多路复用、（M1）数据连接
// 绑定、（M4）SOCKS5 入口、心跳维持与断线指数退避重连（1s×2 + 抖动，上限 60s，
// 设计文档 §6）。重连后重新 REGISTER → 服务端原子替换映射，无端口残留。
package client

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Cypewake/ghostpipe/internal/auth"
	"github.com/Cypewake/ghostpipe/internal/mux"
	"github.com/Cypewake/ghostpipe/internal/protocol"
	"github.com/Cypewake/ghostpipe/internal/socks5"
	"github.com/Cypewake/ghostpipe/internal/stream"
	"github.com/Cypewake/ghostpipe/internal/transport"
)

// TunnelSpec 一条隧道：VPS 远端端口 → 本地目标
type TunnelSpec struct {
	RemotePort uint16
	Target     string
}

// ParseTunnels 解析 "10022=127.0.0.1:22,10080=192.168.1.10:80" 形式的隧道清单
func ParseTunnels(spec string) ([]TunnelSpec, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	var out []TunnelSpec
	for _, item := range strings.Split(spec, ",") {
		kv := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("隧道格式非法: %q（应为 远端端口=本地目标）", item)
		}
		port, err := strconv.Atoi(strings.TrimSpace(kv[0]))
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("远端端口非法: %q", kv[0])
		}
		target := strings.TrimSpace(kv[1])
		if _, _, err := net.SplitHostPort(target); err != nil {
			return nil, fmt.Errorf("本地目标非法: %q（应为 host:port）", target)
		}
		out = append(out, TunnelSpec{RemotePort: uint16(port), Target: target})
	}
	return out, nil
}

// Config 客户端配置
type Config struct {
	ServerAddr  string
	PSK         []byte
	Fingerprint string
	UseTLS      bool
	WS          bool
	Mode        string
	Socks5Addr  string
	Tunnels     []TunnelSpec
}

type activeSession struct {
	conn *transport.Conn
	mux  *mux.Mux // mux 模式非 nil
}

// Client 客户端实例
type Client struct {
	cfg         Config
	inst        [8]byte
	mu          sync.Mutex
	cur         *activeSession
	established atomic.Bool
	stopped     atomic.Bool
	stopCh      chan struct{}
}

// Run 阻塞运行客户端主循环（连接 → 认证 → 注册 → 心跳 → 断线退避重连）
func Run(cfg Config) error {
	cl, err := New(cfg)
	if err != nil {
		return err
	}
	return cl.loop()
}

// Start 后台 goroutine 运行客户端，返回句柄供优雅退出（配合 Shutdown）
func Start(cfg Config) (*Client, error) {
	cl, err := New(cfg)
	if err != nil {
		return nil, err
	}
	go func() {
		if err := cl.loop(); err != nil {
			log.Printf("[client] 主循环异常退出: %v", err)
		}
	}()
	return cl, nil
}

// New 构造客户端（含 SOCKS5 入口初始化）
func New(cfg Config) (*Client, error) {
	cl := &Client{cfg: cfg, stopCh: make(chan struct{})}
	if _, err := rand.Read(cl.inst[:]); err != nil {
		return nil, err
	}
	if cfg.Socks5Addr != "" {
		if cfg.Mode != "mux" {
			return nil, errors.New("SOCKS5 需要 -mode mux（动态目标经 OPEN_ADDR 由服务端出网）")
		}
		ln, err := net.Listen("tcp", cfg.Socks5Addr)
		if err != nil {
			return nil, fmt.Errorf("SOCKS5 监听失败: %w", err)
		}
		log.Printf("[client] SOCKS5 已监听 %s", cfg.Socks5Addr)
		go func() {
			_ = socks5.Serve(ln, cl.openAddr)
		}()
	}
	return cl, nil
}

func (cl *Client) loop() error {
	backoff := time.Second
	for {
		if cl.stopped.Load() {
			return nil
		}
		err := cl.runOnce()
		if cl.stopped.Load() {
			return nil
		}
		if cl.established.CompareAndSwap(true, false) {
			backoff = time.Second // 会话曾建立过 → 重置退避
		}
		wait := backoff + time.Duration(randJitter(int64(backoff)/4+1)) // 随机抖动（设计文档 §6）
		log.Printf("[client] 会话断开: %v → %v 后重连", err, wait.Round(time.Millisecond))
		select {
		case <-time.After(wait):
		case <-cl.stopCh:
			return nil
		}
		if backoff < 60*time.Second {
			backoff *= 2
		}
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
	}
}

// Shutdown 优雅退出：注销全部隧道后断开（设计文档 §6 UNREGISTER）
func (cl *Client) Shutdown() {
	cl.stopped.Store(true)
	close(cl.stopCh)
	cl.mu.Lock()
	sess := cl.cur
	cl.mu.Unlock()
	if sess != nil {
		for _, ts := range cl.cfg.Tunnels {
			_ = sess.conn.Send(protocol.TypeUNREGISTER, 0, protocol.EncodeU16(ts.RemotePort))
		}
		_ = sess.conn.Close()
	}
}

func (cl *Client) runOnce() error {
	nc, err := transport.Dial(cl.cfg.ServerAddr, transport.DialOptions{
		UseTLS:      cl.cfg.UseTLS,
		Fingerprint: cl.cfg.Fingerprint,
		WS:          cl.cfg.WS,
		Timeout:     10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("连接服务端: %w", err)
	}
	c := transport.NewConn(nc, protocol.ProtocolVersion)
	if err := auth.Client(c, cl.cfg.PSK); err != nil {
		_ = c.Close()
		return err
	}
	log.Printf("[client] 双向认证通过 → %s（模式=%s TLS=%v WS=%v）", cl.cfg.ServerAddr, cl.cfg.Mode, cl.cfg.UseTLS, cl.cfg.WS)

	sess := &activeSession{conn: c}
	cl.mu.Lock()
	cl.cur = sess
	cl.mu.Unlock()
	defer func() {
		cl.mu.Lock()
		if cl.cur == sess {
			cl.cur = nil
		}
		cl.mu.Unlock()
		_ = c.Close()
	}()

	// 注册全部隧道（服务端收到即原子替换旧映射）
	for _, ts := range cl.cfg.Tunnels {
		if err := c.Send(protocol.TypeREGISTER, 0, protocol.EncodeRegister(ts.RemotePort, ts.Target, cl.inst)); err != nil {
			return err
		}
	}

	if cl.cfg.Mode == "mux" {
		m := mux.New(c, true)
		sess.mux = m
		m.SetHandlers(
			func(st *mux.Stream, port uint16) { cl.handleOpenTunnel(sess, st, port) },
			func(st *mux.Stream, target string) { cl.handleOpenAddr(st, target) }, // 服务端 SOCKS5 下发：客户端内网拨号
			func(f *protocol.Frame) {
				if f.Type == protocol.TypeREGISTEROK {
					if p, err := protocol.DecodeU16(f.Payload); err == nil {
						log.Printf("[client] 隧道就绪: VPS:%d → %s", p, cl.lookupTarget(p))
					}
				}
			},
		)
		go m.Run()
	} else {
		go cl.m1ReadLoop(sess)
	}
	cl.established.Store(true)

	// 心跳保活：5s 一跳，15s 无入帧判死（最坏感知 ~30s）
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if time.Since(c.LastRecv()) > 15*time.Second {
				return errors.New("心跳超时")
			}
			if err := c.Send(protocol.TypePING, 0, nil); err != nil {
				return err
			}
		case <-c.Done():
			return errors.New("连接断开")
		}
	}
}

// ---- M2：服务端发起的隧道流 ----

func (cl *Client) handleOpenTunnel(sess *activeSession, st *mux.Stream, port uint16) {
	target := cl.lookupTarget(port)
	if target == "" {
		_ = sess.conn.Send(protocol.TypeERROR, st.ID(), protocol.EncodeError(protocol.ErrCodeRemoteRefused, "隧道不存在"))
		_ = st.Close()
		return
	}
	local, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		log.Printf("[client] 本地目标 %s 连接失败: %v", target, err)
		_ = sess.conn.Send(protocol.TypeERROR, st.ID(), protocol.EncodeError(protocol.ErrCodeRemoteRefused, "本地目标拒绝"))
		_ = st.Close()
		return
	}
	go stream.Pump(local, st)
}

// ---- M1：数据连接绑定 ----

func (cl *Client) m1ReadLoop(sess *activeSession) {
	for {
		f, err := sess.conn.Receive()
		if err != nil {
			return
		}
		switch f.Type {
		case protocol.TypeOPEN:
			port, token, err := protocol.DecodeOpenM1(f.Payload)
			if err != nil {
				log.Printf("[client] OPEN 非法: %v", err)
				continue
			}
			go cl.handleOpenM1(port, token)
		case protocol.TypeREGISTEROK:
			if p, err := protocol.DecodeU16(f.Payload); err == nil {
				log.Printf("[client] 隧道就绪: VPS:%d → %s", p, cl.lookupTarget(p))
			}
		case protocol.TypePING:
			_ = sess.conn.Send(protocol.TypePONG, 0, nil)
		}
	}
}

func (cl *Client) handleOpenM1(port uint16, token [32]byte) {
	fail := func() {
		cl.mu.Lock()
		sess := cl.cur
		cl.mu.Unlock()
		if sess != nil {
			// 按 token 回收服务端等待中的外部连接
			_ = sess.conn.Send(protocol.TypeERROR, 0,
				protocol.EncodeError(protocol.ErrCodeRemoteRefused, "rr:"+hex.EncodeToString(token[:])))
		}
	}
	target := cl.lookupTarget(port)
	if target == "" {
		fail()
		return
	}
	local, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		log.Printf("[client] 本地目标 %s 连接失败: %v", target, err)
		fail()
		return
	}
	dc, err := transport.Dial(cl.cfg.ServerAddr, transport.DialOptions{
		UseTLS: cl.cfg.UseTLS, Fingerprint: cl.cfg.Fingerprint, WS: cl.cfg.WS, Timeout: 10 * time.Second,
	})
	if err != nil {
		log.Printf("[client] 数据连接拨号失败: %v", err)
		_ = local.Close()
		fail()
		return
	}
	dconn := transport.NewConn(dc, protocol.ProtocolVersion)
	if err := dconn.Send(protocol.TypeDATABIND, 0, token[:]); err != nil {
		_ = local.Close()
		_ = dc.Close()
		fail()
		return
	}
	// 消费服务端在数据连接上先发的挑战帧（AUTH_REQ，连接角色自描述的实现细节，
	// 见 docs/开发文档.md §实现偏差）：不消费会污染响应字节流
	if stray, err := dconn.Receive(); err != nil || stray.Type != protocol.TypeAUTHREQ {
		log.Printf("[client] 数据连接挑战帧异常，放弃绑定")
		_ = local.Close()
		_ = dc.Close()
		fail()
		return
	}
	stream.Pump(local, stream.NewConnStream(dc))
}

// ---- M4：SOCKS5 动态出口 ----

// handleOpenAddr 服务端 SOCKS5 入口下发的动态目标 → 客户端内网拨号（frp socks5 插件等价方向）。
// 服务端把外部用户 CONNECT 的 target 经 OPEN_ADDR(S→C) 送到这里，由客户端在所在内网出网。
func (cl *Client) handleOpenAddr(st *mux.Stream, target string) {
	fail := func() {
		cl.mu.Lock()
		sess := cl.cur
		cl.mu.Unlock()
		if sess != nil {
			_ = sess.conn.Send(protocol.TypeERROR, st.ID(),
				protocol.EncodeError(protocol.ErrCodeRemoteRefused, "内网目标拒绝: "+target))
		}
		_ = st.Close()
	}
	local, err := net.DialTimeout("tcp", target, 8*time.Second)
	if err != nil {
		log.Printf("[client] 内网目标 %s 连接失败: %v", target, err)
		fail()
		return
	}
	go stream.Pump(local, st)
}

// openAddr 客户端本地 SOCKS5（-socks5）的拨号回调：经隧道由服务端出网。
func (cl *Client) openAddr(target string) (io.ReadWriteCloser, error) {
	cl.mu.Lock()
	sess := cl.cur
	cl.mu.Unlock()
	if sess == nil || sess.mux == nil {
		return nil, errors.New("隧道未连接")
	}
	return sess.mux.OpenAddr(target)
}

func (cl *Client) lookupTarget(port uint16) string {
	for _, ts := range cl.cfg.Tunnels {
		if ts.RemotePort == port {
			return ts.Target
		}
	}
	return ""
}

func randJitter(n int64) int64 {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return v.Int64()
}
