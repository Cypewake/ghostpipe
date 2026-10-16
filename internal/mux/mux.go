// Package mux 实现 M2 多路复用与双层信用流控（设计文档 §5.3）。
//
// 关键规则（全部来自对抗复核修正）：
//   - StreamID：client 奇数 / server 偶数，单调递增，永不复用（杜绝迟到帧误入新流）
//   - 双层窗口：流级 256KB + 连接级 1MB
//   - 连接级信用在帧读入内存后即归还 → 流关闭不泄漏连接级窗口（第二轮 #4 修正）
//   - 流级信用在本地应用消费后归还 → 端到端背压
//   - 控制帧（非 DATA）不受任何窗口约束 → 无"双向等 CREDIT"死锁（第二轮 #3 修正）
//   - 已关闭流的 DATA/CREDIT 静默丢弃 + 计数（第二轮 #8 修正）
//
// 并发模型（实现级设计）：
//   - 单读循环分发，读循环触发的应答（连接级 CREDIT/PONG）走非阻塞队列，绝不阻塞读循环
//   - 唯一写协程串行化出帧——消除"读写循环互相等对方读"的系统级死锁
//     （实测教训：同步 Send 在背压下与对端读循环互等，20 流并发即死锁）
//   - 每流独立写互斥；应用路径的发送经队列阻塞等待，连接死亡即唤醒
package mux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"ghostpipe/internal/protocol"
	"ghostpipe/internal/transport"
)

// 流控常量（设计文档 §5.3）
const (
	StreamWindow = 256 << 10  // 流级窗口 256KB
	ConnWindow   = 1 << 20    // 连接级窗口 1MB
	MaxStreams   = 256        // 每连接并发流上限（resource-limit）
	MaxID        = 0x7fffffff // StreamID 触顶 → id-exhausted

	sendQueueLen = 4096 // 发送队列深度
)

var (
	ErrConnClosed    = errors.New("复用连接已关闭")
	ErrIDExhausted   = errors.New("StreamID 已耗尽（id-exhausted）")
	ErrResourceLimit = errors.New("并发流数超限（resource-limit）")
)

// RemoteError 远端通过 ERROR 帧上报的错误
type RemoteError struct {
	Code protocol.ErrCode
	Msg  string
}

func (e *RemoteError) Error() string { return fmt.Sprintf("远端错误 %s: %s", e.Code, e.Msg) }

// ---- 发送队列 ----

type sendMsg struct {
	typ     protocol.FrameType
	sid     uint32
	payload []byte
	errc    chan error // nil = 尽力而为（失败/丢弃不通知）
}

// Mux 单连接上的多路复用器
type Mux struct {
	conn       *transport.Conn
	clientSide bool

	onOpenTunnel func(s *Stream, remotePort uint16) // 收到 OPEN（对端请求隧道流）
	onOpenAddr   func(s *Stream, target string)     // 收到 OPEN_ADDR（对端请求动态流）
	onControl    func(f *protocol.Frame)            // REGISTER/REGISTER_OK/UNREGISTER

	mu         sync.Mutex
	cond       *sync.Cond
	streams    map[uint32]*Stream
	closedIDs  map[uint32]bool
	nextID     uint32
	connCredit int64 // 我方在连接级写方向上的剩余信用
	err        error

	sendCh   chan sendMsg
	doneCh   chan struct{}
	doneOnce sync.Once

	lateFrames atomic.Uint64
}

// New clientSide 决定 StreamID 奇偶与起始值
func New(c *transport.Conn, clientSide bool) *Mux {
	m := &Mux{
		conn:       c,
		clientSide: clientSide,
		streams:    make(map[uint32]*Stream),
		closedIDs:  make(map[uint32]bool),
		connCredit: ConnWindow,
		sendCh:     make(chan sendMsg, sendQueueLen),
		doneCh:     make(chan struct{}),
	}
	if clientSide {
		m.nextID = 1 // 客户端奇数
	} else {
		m.nextID = 2 // 服务端偶数
	}
	m.cond = sync.NewCond(&m.mu)
	go m.sender() // 唯一写协程
	return m
}

// SetHandlers 注入回调（必须在 Run 之前）
func (m *Mux) SetHandlers(onOpenTunnel func(*Stream, uint16), onOpenAddr func(*Stream, string), onControl func(*protocol.Frame)) {
	m.onOpenTunnel = onOpenTunnel
	m.onOpenAddr = onOpenAddr
	m.onControl = onControl
}

// Run 读循环：阻塞直到连接死亡或协议违规
func (m *Mux) Run() {
	for {
		f, err := m.conn.Receive()
		if err != nil {
			m.shutdown(fmt.Errorf("读循环退出: %w", err))
			return
		}
		if !m.dispatch(f) {
			return
		}
	}
}

// sender 唯一写协程：串行化全部出帧
func (m *Mux) sender() {
	for {
		select {
		case msg := <-m.sendCh:
			if err := m.conn.Send(msg.typ, msg.sid, msg.payload); err != nil {
				m.shutdown(err)
				m.rejectPending()
				return
			}
			if msg.errc != nil {
				msg.errc <- nil
			}
		case <-m.doneCh:
			return
		}
	}
}

func (m *Mux) rejectPending() {
	for {
		select {
		case msg := <-m.sendCh:
			if msg.errc != nil {
				msg.errc <- ErrConnClosed
			}
		default:
			return
		}
	}
}

// sendAsync 应用路径发送：入队等待写协程结果；连接死亡立即返回错误
func (m *Mux) sendAsync(t protocol.FrameType, sid uint32, payload []byte) error {
	msg := sendMsg{typ: t, sid: sid, payload: payload, errc: make(chan error, 1)}
	select {
	case m.sendCh <- msg:
	case <-m.doneCh:
		return m.closeErr()
	}
	select {
	case err := <-msg.errc:
		return err
	case <-m.doneCh:
		return m.closeErr()
	}
}

// trySend 读循环路径的应答帧：队列满则丢弃（自愈——后续帧会再触发信用/应答）
func (m *Mux) trySend(t protocol.FrameType, sid uint32, payload []byte) {
	select {
	case m.sendCh <- sendMsg{typ: t, sid: sid, payload: payload}:
	default:
	}
}

func (m *Mux) closeErr() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	return ErrConnClosed
}

// LateFrames 已关闭流上的迟到帧计数（观测用，设计文档 §5.3）
func (m *Mux) LateFrames() uint64 { return m.lateFrames.Load() }

func (m *Mux) dispatch(f *protocol.Frame) bool {
	switch f.Type {
	case protocol.TypeDATA:
		return m.handleData(f)
	case protocol.TypeCREDIT:
		return m.handleCredit(f)
	case protocol.TypeCLOSE:
		m.handleClose(f.StreamID)
	case protocol.TypeERROR:
		return m.handleError(f)
	case protocol.TypePING:
		m.trySend(protocol.TypePONG, f.StreamID, nil)
	case protocol.TypePONG:
		// 活性由 transport.Conn.LastRecv 统一跟踪
	case protocol.TypeOPEN:
		return m.handleOpen(f, false)
	case protocol.TypeOPENADDR:
		return m.handleOpen(f, true)
	case protocol.TypeREGISTER, protocol.TypeREGISTEROK, protocol.TypeUNREGISTER:
		if m.onControl != nil {
			h := m.onControl
			go h(f) // 异步执行，绝不阻塞读循环
		}
	default:
		m.shutdown(fmt.Errorf("%w: 未知帧类型 0x%02x", protocol.ErrProtoViolation, byte(f.Type)))
		return false
	}
	return true
}

// handleData DATA 分发。连接级信用无条件归还（含迟到帧——发送方已消耗）。
func (m *Mux) handleData(f *protocol.Frame) bool {
	n := uint32(len(f.Payload))
	m.mu.Lock()
	if st := m.streams[f.StreamID]; st != nil {
		st.buf = append(st.buf, f.Payload)
		st.bufLen += len(f.Payload)
		// 防御：对端违反窗口协议
		if st.bufLen > StreamWindow*2 {
			m.mu.Unlock()
			m.shutdown(fmt.Errorf("%w: 流 %d 缓冲超限", protocol.ErrProtoViolation, f.StreamID))
			return false
		}
		m.cond.Broadcast()
		m.mu.Unlock()
	} else if m.closedIDs[f.StreamID] {
		m.lateFrames.Add(1) // 静默丢弃 + 计数，不断连（in-flight CLOSE 竞态）
		m.mu.Unlock()
	} else {
		m.mu.Unlock()
		m.shutdown(fmt.Errorf("%w: DATA 指向未知流 %d", protocol.ErrProtoViolation, f.StreamID))
		return false
	}
	m.trySend(protocol.TypeCREDIT, 0, protocol.EncodeCredit(n)) // 连接级信用读入即回
	return true
}

func (m *Mux) handleCredit(f *protocol.Frame) bool {
	delta, err := protocol.DecodeCredit(f.Payload)
	if err != nil {
		m.shutdown(fmt.Errorf("%w: CREDIT Payload 非法", protocol.ErrProtoViolation))
		return false
	}
	m.mu.Lock()
	if f.StreamID == 0 {
		m.connCredit += int64(delta)
	} else if st := m.streams[f.StreamID]; st != nil {
		st.streamCredit += int64(delta)
	}
	// 已关闭流的 CREDIT：忽略（迟到帧）
	m.cond.Broadcast()
	m.mu.Unlock()
	return true
}

func (m *Mux) handleClose(sid uint32) {
	m.mu.Lock()
	st := m.streams[sid]
	if st == nil {
		m.mu.Unlock()
		return // 迟到/未知 CLOSE 忽略
	}
	// v1 无半关闭：CLOSE 即双向关闭（设计文档 §6）
	st.remoteClosed = true
	st.readErr = io.EOF
	st.writeErr = io.ErrClosedPipe
	st.buf = nil
	st.bufLen = 0
	delete(m.streams, sid)
	m.closedIDs[sid] = true
	m.cond.Broadcast()
	m.mu.Unlock()
}

func (m *Mux) handleError(f *protocol.Frame) bool {
	code, msg := protocol.DecodeError(f.Payload)
	if code == protocol.ErrCodeProtoViolation {
		m.shutdown(fmt.Errorf("远端报告协议违规: %s", msg))
		return false
	}
	m.mu.Lock()
	st := m.streams[f.StreamID]
	if st == nil {
		m.mu.Unlock()
		return true // 迟到 ERROR 忽略
	}
	re := &RemoteError{Code: code, Msg: msg}
	st.readErr = re
	st.writeErr = re
	delete(m.streams, f.StreamID)
	m.closedIDs[f.StreamID] = true
	m.cond.Broadcast()
	m.mu.Unlock()
	return true
}

func (m *Mux) handleOpen(f *protocol.Frame, isAddr bool) bool {
	m.mu.Lock()
	if f.StreamID == 0 || m.streams[f.StreamID] != nil || m.closedIDs[f.StreamID] {
		m.mu.Unlock()
		m.shutdown(fmt.Errorf("%w: OPEN 流 ID 非法 %d", protocol.ErrProtoViolation, f.StreamID))
		return false
	}
	if len(m.streams) >= MaxStreams {
		m.mu.Unlock()
		m.trySend(protocol.TypeERROR, f.StreamID, protocol.EncodeError(protocol.ErrCodeResourceLimit, "并发流超限"))
		return true
	}
	// 先注册再交回调：保证后续 DATA 一定能路由到
	st := &Stream{id: f.StreamID, m: m, streamCredit: StreamWindow}
	m.streams[f.StreamID] = st
	m.mu.Unlock()

	if isAddr {
		if m.onOpenAddr == nil {
			m.shutdown(fmt.Errorf("%w: 收到未支持的 OPEN_ADDR", protocol.ErrProtoViolation))
			return false
		}
		h := m.onOpenAddr
		go h(st, string(f.Payload))
	} else {
		if len(f.Payload) < 2 {
			_ = st.Close()
			return true
		}
		port := binary.BigEndian.Uint16(f.Payload)
		if m.onOpenTunnel == nil {
			m.shutdown(fmt.Errorf("%w: 收到未支持的 OPEN", protocol.ErrProtoViolation))
			return false
		}
		h := m.onOpenTunnel
		go h(st, port)
	}
	return true
}

// ---- 出向开流 ----

func (m *Mux) newStream() (*Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	if len(m.streams) >= MaxStreams {
		return nil, ErrResourceLimit
	}
	if m.nextID > MaxID {
		return nil, ErrIDExhausted
	}
	id := m.nextID
	m.nextID += 2 // 单调递增，永不复用
	st := &Stream{id: id, m: m, streamCredit: StreamWindow}
	m.streams[id] = st
	return st, nil
}

// OpenTunnel 服务端 → 客户端：按隧道端口开流（M2）
func (m *Mux) OpenTunnel(port uint16) (*Stream, error) {
	st, err := m.newStream()
	if err != nil {
		return nil, err
	}
	if err := m.sendAsync(protocol.TypeOPEN, st.id, protocol.EncodeU16(port)); err != nil {
		m.discard(st)
		return nil, err
	}
	return st, nil
}

// OpenAddr 客户端 → 服务端：按动态地址开流（M4 SOCKS5）
func (m *Mux) OpenAddr(target string) (*Stream, error) {
	if target == "" || len(target) > 255 {
		return nil, errors.New("目标地址非法")
	}
	st, err := m.newStream()
	if err != nil {
		return nil, err
	}
	if err := m.sendAsync(protocol.TypeOPENADDR, st.id, []byte(target)); err != nil {
		m.discard(st)
		return nil, err
	}
	return st, nil
}

func (m *Mux) discard(st *Stream) {
	m.mu.Lock()
	if m.streams[st.id] == st {
		delete(m.streams, st.id)
		m.closedIDs[st.id] = true
	}
	m.cond.Broadcast()
	m.mu.Unlock()
}

// ---- Stream ----

// Stream 多路复用流。Read/Write/Close 全部并发安全。
type Stream struct {
	id  uint32
	m   *Mux
	wmu sync.Mutex // 每流写互斥（防多 goroutine 写交错）

	// 以下字段由 m.mu 保护
	buf          [][]byte
	bufLen       int
	readErr      error
	writeErr     error
	streamCredit int64 // 远端授予本流写方向的剩余信用
	localClosed  bool
	remoteClosed bool
}

// ID 流标识
func (s *Stream) ID() uint32 { return s.id }

// Read 阻塞读；消费后归还流级信用
func (s *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	m := s.m
	m.mu.Lock()
	for {
		if s.bufLen > 0 {
			n := 0
			for n < len(p) && len(s.buf) > 0 {
				c := copy(p[n:], s.buf[0])
				s.buf[0] = s.buf[0][c:]
				if len(s.buf[0]) == 0 {
					s.buf = s.buf[1:]
				}
				n += c
			}
			s.bufLen -= n
			delta := uint32(n)
			m.mu.Unlock()
			_ = m.sendAsync(protocol.TypeCREDIT, s.id, protocol.EncodeCredit(delta)) // 流级信用：应用已消费
			return n, nil
		}
		if s.readErr != nil {
			err := s.readErr
			m.mu.Unlock()
			return 0, err
		}
		m.cond.Wait()
	}
}

// Write 阻塞写；分片 ≤ min(16KB, 流信用, 连接信用)
func (s *Stream) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()

	m := s.m
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for total < len(p) {
		if m.err != nil {
			return total, m.err
		}
		if s.writeErr != nil {
			return total, s.writeErr
		}
		if s.localClosed {
			return total, io.ErrClosedPipe
		}
		chunk := int64(len(p) - total)
		if chunk > int64(protocol.MaxPayload) {
			chunk = int64(protocol.MaxPayload)
		}
		if chunk > s.streamCredit {
			chunk = s.streamCredit
		}
		if chunk > m.connCredit {
			chunk = m.connCredit
		}
		if chunk <= 0 {
			m.cond.Wait() // 控制帧豁免窗口 → CREDIT 终将到来，无死锁
			continue
		}
		s.streamCredit -= chunk
		m.connCredit -= chunk
		end := total + int(chunk)
		payload := p[total:end]
		m.mu.Unlock() // 发送期间不持锁，不阻碍读循环与其他流
		err := m.sendAsync(protocol.TypeDATA, s.id, payload)
		m.mu.Lock()
		if err != nil {
			return total, err
		}
		total = end
	}
	return total, nil
}

// Close 双向关闭（v1 无半关闭，设计文档 §6）
func (s *Stream) Close() error {
	m := s.m
	m.mu.Lock()
	if s.localClosed {
		m.mu.Unlock()
		return nil
	}
	s.localClosed = true
	s.readErr = io.EOF
	s.writeErr = io.ErrClosedPipe
	s.buf = nil
	s.bufLen = 0
	delete(m.streams, s.id)
	m.closedIDs[s.id] = true
	m.cond.Broadcast()
	m.mu.Unlock()
	m.trySend(protocol.TypeCLOSE, s.id, nil) // 尽力而为
	return nil
}

// ---- 生命周期 ----

func (m *Mux) shutdown(err error) {
	m.mu.Lock()
	if m.err == nil {
		m.err = err
	}
	for _, st := range m.streams {
		if st.readErr == nil {
			st.readErr = ErrConnClosed
		}
		if st.writeErr == nil {
			st.writeErr = ErrConnClosed
		}
	}
	m.streams = make(map[uint32]*Stream)
	m.cond.Broadcast()
	m.mu.Unlock()
	m.doneOnce.Do(func() { close(m.doneCh) })
	_ = m.conn.Close()
}

// Close 主动关闭整个复用连接
func (m *Mux) Close() error {
	m.shutdown(ErrConnClosed)
	return nil
}
