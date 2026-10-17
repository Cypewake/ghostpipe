// Package server 实现 ghostpipe 服务端（公网 VPS 侧）。
//
// 职责：认证闸门、隧道注册（端口监听）、外部连接接入与分发、心跳判定、
// M1 数据连接 token 绑定。注册替换规则：同端口新 REGISTER 无条件原子替换
// （设计文档 §6，第二轮 #1 修正）；token 未消费在替换/过期时全部回收。
package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"ghostpipe/internal/auth"
	"ghostpipe/internal/mux"
	"ghostpipe/internal/protocol"
	"ghostpipe/internal/socks5"
	"ghostpipe/internal/stream"
	"ghostpipe/internal/transport"
)

// Config 服务端配置
type Config struct {
	Listen     string // 控制监听地址（映射端口绑定同主机的 host 部分）
	PSK        []byte
	UseTLS     bool
	WS         bool   // M3 WebSocket 载体
	Mode       string
	Socks5Addr string // 服务端 SOCKS5 入口（可选，mux 模式；动态目标由客户端内网拨号）
}

// pendingBind M1：已下发 token、等待数据连接绑定的外部连接
type pendingBind struct {
	sess  *session
	ext   net.Conn
	port  uint16
	timer *time.Timer
}

// Server 服务端实例
type Server struct {
	cfg      Config
	pendMu   sync.Mutex
	pendings map[[32]byte]*pendingBind // token → pending（≤64，resource-limit）
	portMu   sync.Mutex
	ports    map[uint16]*session // 全局端口归属：支持跨会话原子替换（设计文档 §6）
	curMu    sync.Mutex
	cur      *session // 当前活跃会话（v1 单客户端；服务端 SOCKS5 入口经此下发 OPEN_ADDR）
}

// Run 启动服务端（阻塞）
func Run(cfg Config) error {
	ln, err := transport.Listen(cfg.Listen, transport.ListenOptions{UseTLS: cfg.UseTLS, WS: cfg.WS})
	if err != nil {
		return err
	}
	s := &Server{cfg: cfg, pendings: make(map[[32]byte]*pendingBind), ports: make(map[uint16]*session)}
	if cfg.Socks5Addr != "" {
		if cfg.Mode != "mux" {
			_ = ln.Close()
			return errors.New("服务端 SOCKS5 需要 mux 模式（动态目标经 OPEN_ADDR 由客户端内网拨号）")
		}
		ln5, err := net.Listen("tcp", cfg.Socks5Addr)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("SOCKS5 监听失败: %w", err)
		}
		log.Printf("[server] SOCKS5 已监听 %s（动态目标由客户端内网出网）", cfg.Socks5Addr)
		go func() { _ = socks5.Serve(ln5, s.socksDial) }()
	}
	log.Printf("[server] 控制端口已监听 %s（模式=%s TLS=%v WS=%v）", cfg.Listen, cfg.Mode, cfg.UseTLS, cfg.WS)
	if cfg.UseTLS {
		log.Printf("[server] 自签证书 SPKI 指纹（客户端 --tls-fingerprint 填这个）: %s", ln.Fingerprint)
	}
	for {
		nc, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(nc)
	}
}

// socksDial 服务端 SOCKS5 入口的拨号回调：把动态目标经 OPEN_ADDR(S→C) 下发给客户端内网拨号。
func (s *Server) socksDial(target string) (io.ReadWriteCloser, error) {
	s.curMu.Lock()
	sess := s.cur
	s.curMu.Unlock()
	if sess == nil || sess.mux == nil {
		return nil, errors.New("无客户端在线")
	}
	return sess.mux.OpenAddr(target)
}

func (s *Server) setCur(sess *session) { s.curMu.Lock(); s.cur = sess; s.curMu.Unlock() }

func (s *Server) clearCur(sess *session) {
	s.curMu.Lock()
	if s.cur == sess {
		s.cur = nil
	}
	s.curMu.Unlock()
}

// handleConn 连接分诊（服务端先说话，设计文档 §4.1）：
//  1. 服务端先发 AUTH_REQ（消除"窥视首帧 ↔ 客户端等挑战"互等竞态）
//  2. 读应答帧：AUTH_RESP → 控制会话；DATA_BIND → M1 数据连接；其他 → 协议违规
func (s *Server) handleConn(nc net.Conn) {
	c := transport.NewConn(nc, protocol.ProtocolVersion)
	_ = nc.SetDeadline(time.Now().Add(auth.HandshakeTimeout + 5*time.Second))

	nonceS, err := auth.ServerChallenge(c)
	if err != nil {
		log.Printf("[server] 发送挑战失败: %v", err)
		_ = c.Close()
		return
	}
	first, err := c.Receive()
	if err != nil {
		log.Printf("[server] 握手帧读取失败: %v", err)
		_ = c.Close()
		return
	}

	switch first.Type {
	case protocol.TypeAUTHRESP:
		if err := auth.ServerVerify(c, s.cfg.PSK, nonceS, first); err != nil {
			log.Printf("[server] 认证失败: %v", err)
			_ = c.Close()
			return
		}
		_ = nc.SetDeadline(time.Time{}) // 会话期不再受握手时限约束
		log.Printf("[server] 客户端已通过双向认证")
		sess := &session{
			srv:     s,
			conn:    c,
			tunnels: make(map[uint16]*tunnel),
		}
		s.setCur(sess)
		sess.serve()
	case protocol.TypeDATABIND:
		if s.cfg.Mode != "conn" {
			log.Printf("[server] mux 模式收到 DATA_BIND（proto-violation）")
			_ = c.Close()
			return
		}
		_ = nc.SetDeadline(time.Time{})
		s.handleDataBind(c, first)
	default:
		log.Printf("[server] 应答帧类型非法: %s（proto-violation）", first.Type)
		_ = c.Close()
	}
}

// ---- token 登记（M1）----

func (s *Server) addPending(sess *session, token [32]byte, ext net.Conn, port uint16, ttl time.Duration) bool {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	if len(s.pendings) >= 64 { // resource-limit：pending token 上限（设计文档 §5.3）
		return false
	}
	pb := &pendingBind{sess: sess, ext: ext, port: port}
	pb.timer = time.AfterFunc(ttl, func() {
		if old := s.removePending(token); old != nil {
			log.Printf("[server] token 过期，回收外部连接 port=%d", port)
			_ = old.ext.Close()
		}
	})
	s.pendings[token] = pb
	return true
}

func (s *Server) removePending(token [32]byte) *pendingBind {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	pb := s.pendings[token]
	if pb != nil {
		pb.timer.Stop()
		delete(s.pendings, token)
	}
	return pb
}

func (s *Server) clearPendingBySession(sess *session) {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	for token, pb := range s.pendings {
		if pb.sess == sess {
			pb.timer.Stop()
			_ = pb.ext.Close()
			delete(s.pendings, token)
		}
	}
}

func (s *Server) handleDataBind(c *transport.Conn, first *protocol.Frame) {
	var token [32]byte
	copy(token[:], first.Payload)
	pb := s.removePending(token)
	if pb == nil {
		log.Printf("[server] DATA_BIND 拒绝：token 无效或已过期")
		_ = c.Close()
		return
	}
	log.Printf("[server] 数据连接已绑定 port=%d", pb.port)
	stream.Pump(pb.ext, stream.NewConnStream(c.Raw()))
}

// ---- 会话 ----

type tunnel struct {
	target string
	ln     net.Listener
}

type session struct {
	srv     *Server
	conn    *transport.Conn
	tunnels map[uint16]*tunnel
	tmu     sync.Mutex
	mux     *mux.Mux
}

func (sess *session) serve() {
	if sess.srv.cfg.Mode == "mux" {
		m := mux.New(sess.conn, false)
		sess.mux = m
		m.SetHandlers(
			nil, // 服务端只发 OPEN，不收（收到即协议违规）
			sess.onOpenAddr,
			sess.handleControlFrame,
		)
		go m.Run()
	} else {
		go sess.readLoop()
	}
	sess.heartbeatLoop()
}

func (sess *session) readLoop() {
	for {
		f, err := sess.conn.Receive()
		if err != nil {
			sess.teardown()
			return
		}
		sess.handleControlFrame(f)
	}
}

// heartbeatLoop 心跳：5s 一跳，15s 无任何入帧即断开（最坏感知 ~30s，设计文档 §6）
func (sess *session) heartbeatLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if time.Since(sess.conn.LastRecv()) > 15*time.Second {
				log.Printf("[server] 心跳超时，断开客户端连接")
				sess.conn.Close()
				sess.teardown()
				return
			}
			_ = sess.conn.Send(protocol.TypePING, 0, nil)
		case <-sess.conn.Done():
			sess.teardown()
			return
		}
	}
}

func (sess *session) handleControlFrame(f *protocol.Frame) {
	switch f.Type {
	case protocol.TypeREGISTER:
		port, target, inst, err := protocol.DecodeRegister(f.Payload)
		if err != nil {
			log.Printf("[server] REGISTER 非法: %v", err)
			_ = sess.conn.Send(protocol.TypeERROR, 0, protocol.EncodeError(protocol.ErrCodeProtoViolation, "REGISTER 非法"))
			_ = sess.conn.Close()
			return
		}
		if err := sess.registerTunnel(port, target); err != nil {
			log.Printf("[server] 隧道注册失败 %d→%s: %v", port, target, err)
			_ = sess.conn.Send(protocol.TypeERROR, 0, protocol.EncodeError(protocol.ErrCodeTunnelConflict, err.Error()))
			return
		}
		log.Printf("[server] 隧道注册: VPS:%d → %s（实例 %x）", port, target, inst)
		_ = sess.conn.Send(protocol.TypeREGISTEROK, 0, protocol.EncodeU16(port))
	case protocol.TypeUNREGISTER:
		port, _ := protocol.DecodeU16(f.Payload)
		sess.unregisterTunnel(port)
	case protocol.TypeERROR:
		code, msg := protocol.DecodeError(f.Payload)
		if code == protocol.ErrCodeRemoteRefused && strings.HasPrefix(msg, "rr:") {
			// M1：client 本地目标拨号失败，按 token 回收等待中的外部连接
			if b, err := hex.DecodeString(msg[3:]); err == nil && len(b) == 32 {
				var token [32]byte
				copy(token[:], b)
				if pb := sess.srv.removePending(token); pb != nil {
					_ = pb.ext.Close()
				}
			}
		} else {
			log.Printf("[server] 客户端上报错误: %s %s", code, msg)
		}
	case protocol.TypePING: // 仅 M1 读循环路径（mux 模式由 mux 应答）
		_ = sess.conn.Send(protocol.TypePONG, 0, nil)
	}
}

// registerTunnel 端口原子替换：
//   - 同会话重注册：关旧 listener + 清旧 pending（第二轮 #7 修正）
//   - 跨会话抢占（旧会话心跳未超时、新会话已连入）：按全局端口归属表强制接管
func (sess *session) registerTunnel(port uint16, target string) error {
	// 全局抢占：通知旧会话释放端口
	sess.srv.portMu.Lock()
	prev := sess.srv.ports[port]
	sess.srv.ports[port] = sess
	sess.srv.portMu.Unlock()
	if prev != nil && prev != sess {
		prev.dropTunnel(port)
		log.Printf("[server] 隧道 %d 原子替换（跨会话接管旧实例）", port)
	}

	sess.tmu.Lock()
	if old := sess.tunnels[port]; old != nil {
		_ = old.ln.Close()
		sess.srv.clearPendingBySessionPort(sess, port)
		log.Printf("[server] 隧道 %d 原子替换（同会话重注册）", port)
	}
	host := sess.srv.listenHost()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		sess.srv.portMu.Lock()
		if sess.srv.ports[port] == sess {
			delete(sess.srv.ports, port)
		}
		sess.srv.portMu.Unlock()
		return err
	}
	t := &tunnel{target: target, ln: ln}
	sess.tunnels[port] = t
	sess.tmu.Unlock()
	go sess.acceptExternal(t, port)
	return nil
}

func (sess *session) unregisterTunnel(port uint16) {
	sess.tmu.Lock()
	t := sess.tunnels[port]
	if t != nil {
		delete(sess.tunnels, port)
	}
	sess.tmu.Unlock()
	sess.srv.releasePort(port, sess)
	if t != nil {
		_ = t.ln.Close()
		log.Printf("[server] 隧道注销: VPS:%d", port)
	}
}

// dropTunnel 跨会话抢占时由新会话调用：强制关闭本会话对该端口的占用
func (sess *session) dropTunnel(port uint16) {
	sess.tmu.Lock()
	t := sess.tunnels[port]
	if t != nil {
		delete(sess.tunnels, port)
	}
	sess.tmu.Unlock()
	sess.srv.clearPendingBySessionPort(sess, port)
	if t != nil {
		_ = t.ln.Close()
	}
}

func (s *Server) releasePort(port uint16, sess *session) {
	s.portMu.Lock()
	defer s.portMu.Unlock()
	if s.ports[port] == sess {
		delete(s.ports, port)
	}
}

func (sess *session) acceptExternal(t *tunnel, port uint16) {
	for {
		ext, err := t.ln.Accept()
		if err != nil {
			return // 监听器已关（替换/注销/断连）
		}
		if sess.srv.cfg.Mode == "mux" {
			st, err := sess.mux.OpenTunnel(port)
			if err != nil {
				_ = ext.Close()
				continue
			}
			go stream.Pump(ext, st)
		} else {
			var token [32]byte
			if _, err := rand.Read(token[:]); err != nil {
				_ = ext.Close()
				continue
			}
			if !sess.srv.addPending(sess, token, ext, port, 10*time.Second) {
				log.Printf("[server] pending 超限，拒绝外部连接 port=%d", port)
				_ = ext.Close()
				continue
			}
			if err := sess.conn.Send(protocol.TypeOPEN, 0, protocol.EncodeOpenM1(port, token)); err != nil {
				sess.srv.removePending(token)
				_ = ext.Close()
				return
			}
		}
	}
}

// onOpenAddr M4：SOCKS5 动态目标出网
func (sess *session) onOpenAddr(st *mux.Stream, target string) {
	local, err := net.DialTimeout("tcp", target, 8*time.Second)
	if err != nil {
		log.Printf("[server] 动态目标 %s 连接失败: %v", target, err)
		_ = sess.conn.Send(protocol.TypeERROR, st.ID(), protocol.EncodeError(protocol.ErrCodeRemoteRefused, "目标拒绝"))
		_ = st.Close()
		return
	}
	go stream.Pump(local, st)
}

func (sess *session) teardown() {
	sess.srv.clearCur(sess)
	sess.tmu.Lock()
	ts := sess.tunnels
	sess.tunnels = make(map[uint16]*tunnel)
	sess.tmu.Unlock()
	for port, t := range ts {
		_ = t.ln.Close()
		sess.srv.releasePort(port, sess)
	}
	sess.srv.clearPendingBySession(sess)
	if sess.mux != nil {
		_ = sess.mux.Close()
	}
}

// listenHost 映射端口与控制端口绑定同一 host（默认 127.0.0.1，VPS 上用 -listen 0.0.0.0:port）
func (s *Server) listenHost() string {
	host, _, err := net.SplitHostPort(s.cfg.Listen)
	if err != nil || host == "" {
		return "127.0.0.1"
	}
	return host
}

func (s *Server) clearPendingBySessionPort(sess *session, port uint16) {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	for token, pb := range s.pendings {
		if pb.sess == sess && pb.port == port {
			pb.timer.Stop()
			_ = pb.ext.Close()
			delete(s.pendings, token)
		}
	}
}
