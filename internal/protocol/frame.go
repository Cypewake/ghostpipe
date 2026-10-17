// Package protocol 实现 ghostpipe 自定义二进制帧协议。
//
// 帧格式（13 字节定长头，所有多字节整数网络字节序/大端）：
//
//	+--------+-----+------+-------+-----------+----------------+
//	| Magic  | Ver | Type | Flags | StreamID  | Length         |
//	| 2B     | 1B  | 1B   | 1B    | 4B        | 4B（仅 Payload）|
//	| 0x4750 |     |      | 恒 0  |           | ≤ 16KB         |
//	+--------+-----+------+-------+-----------+----------------+
//
// 安全规则（设计文档 §3.1）：
//   - Magic 不符 = 协议违规 → 断连
//   - Length 先校验后分配缓冲（防恶意 Length 预分配耗尽内存）
//   - 会话内每帧复验 Ver
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// 协议常量
const (
	MagicByte0      = 0x47 // 'G'
	MagicByte1      = 0x50 // 'P'
	HeaderSize      = 13
	MaxPayload      = 16 * 1024
	ProtocolVersion = 1
)

// FrameType 信令类型（设计文档 §3.2）
type FrameType byte

const (
	TypeAUTHREQ    FrameType = 0x01
	TypeAUTHRESP   FrameType = 0x02
	TypeAUTHOK     FrameType = 0x03
	TypeDATABIND   FrameType = 0x04
	TypeREGISTER   FrameType = 0x10
	TypeREGISTEROK FrameType = 0x11
	TypeUNREGISTER FrameType = 0x12
	TypeOPEN       FrameType = 0x20 // S→C：M1 携带 port+token；M2 携带 port（StreamID=新流）
	TypeOPENOK     FrameType = 0x21 // 保留（v1 实现未用，前向兼容）
	TypeOPENADDR   FrameType = 0x22 // 双向：SOCKS5 动态目标开流，接收方拨号（Payload=target 字符串）
	TypeDATA       FrameType = 0x30
	TypeCREDIT     FrameType = 0x31 // StreamID=0 表示连接级
	TypeCLOSE      FrameType = 0x40
	TypeERROR      FrameType = 0x50
	TypePING       FrameType = 0x60
	TypePONG       FrameType = 0x61
)

// String 便于日志输出
func (t FrameType) String() string {
	names := map[FrameType]string{
		TypeAUTHREQ: "AUTH_REQ", TypeAUTHRESP: "AUTH_RESP", TypeAUTHOK: "AUTH_OK",
		TypeDATABIND: "DATA_BIND", TypeREGISTER: "REGISTER", TypeREGISTEROK: "REGISTER_OK",
		TypeUNREGISTER: "UNREGISTER", TypeOPEN: "OPEN", TypeOPENOK: "OPEN_OK",
		TypeOPENADDR: "OPEN_ADDR", TypeDATA: "DATA", TypeCREDIT: "CREDIT",
		TypeCLOSE: "CLOSE", TypeERROR: "ERROR", TypePING: "PING", TypePONG: "PONG",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(0x%02x)", byte(t))
}

// ErrCode 错误码（设计文档 §3.2）
type ErrCode uint16

const (
	ErrCodeAuthFailed     ErrCode = 1
	ErrCodeVerUnsupported ErrCode = 2
	ErrCodeDupHandshake   ErrCode = 3
	ErrCodeRemoteRefused  ErrCode = 4
	ErrCodeResourceLimit  ErrCode = 5
	ErrCodeIDExhausted    ErrCode = 6
	ErrCodeProtoViolation ErrCode = 7
	ErrCodeTunnelConflict ErrCode = 8
)

func (c ErrCode) String() string {
	names := map[ErrCode]string{
		ErrCodeAuthFailed: "auth-failed", ErrCodeVerUnsupported: "ver-unsupported",
		ErrCodeDupHandshake: "dup-handshake", ErrCodeRemoteRefused: "remote-refused",
		ErrCodeResourceLimit: "resource-limit", ErrCodeIDExhausted: "id-exhausted",
		ErrCodeProtoViolation: "proto-violation", ErrCodeTunnelConflict: "tunnel-conflict",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("err-%d", uint16(c))
}

// ErrProtoViolation 协议违规统一错误（调用方据此断连）
var ErrProtoViolation = errors.New("protocol violation")

// Frame 一条完整的协议帧
type Frame struct {
	Ver      byte
	Type     FrameType
	StreamID uint32
	Payload  []byte
}

// WriteFrame 编码并写出一帧（调用方需自行保证写串行化，见 transport.Conn）
func WriteFrame(w io.Writer, ver byte, t FrameType, streamID uint32, payload []byte) error {
	if len(payload) > MaxPayload {
		return fmt.Errorf("payload %d 字节超过上限 %d", len(payload), MaxPayload)
	}
	var h [HeaderSize]byte
	h[0] = MagicByte0
	h[1] = MagicByte1
	h[2] = ver
	h[3] = byte(t)
	h[4] = 0 // Flags 恒 0（设计文档 §3.1）
	binary.BigEndian.PutUint32(h[5:9], streamID)
	binary.BigEndian.PutUint32(h[9:13], uint32(len(payload)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

// ReadFrame 读取一帧。expectVer>0 时逐帧复验会话版本。
// 先校验 Magic/Ver/Length 再分配缓冲，任何不符返回 ErrProtoViolation。
func ReadFrame(r io.Reader, expectVer byte) (*Frame, error) {
	var h [HeaderSize]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err // io.EOF / io.ErrUnexpectedEOF（半帧）
	}
	if h[0] != MagicByte0 || h[1] != MagicByte1 {
		return nil, fmt.Errorf("%w: Magic 错误 0x%02x%02x", ErrProtoViolation, h[0], h[1])
	}
	if expectVer != 0 && h[2] != expectVer {
		return nil, fmt.Errorf("%w: 帧 Ver=%d 与会话 Ver=%d 不符", ErrProtoViolation, h[2], expectVer)
	}
	n := binary.BigEndian.Uint32(h[9:13])
	if n > MaxPayload {
		return nil, fmt.Errorf("%w: Length=%d 超过上限 %d", ErrProtoViolation, n, MaxPayload)
	}
	f := &Frame{
		Ver:      h[2],
		Type:     FrameType(h[3]),
		StreamID: binary.BigEndian.Uint32(h[5:9]),
	}
	if n > 0 {
		f.Payload = make([]byte, n) // 校验通过后才分配
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// ---- Payload 编解码辅助 ----

// EncodeError ERROR Payload：code(2B) + msg
func EncodeError(code ErrCode, msg string) []byte {
	b := make([]byte, 2, 2+len(msg))
	binary.BigEndian.PutUint16(b, uint16(code))
	return append(b, msg...)
}

// DecodeError 解析 ERROR Payload
func DecodeError(p []byte) (ErrCode, string) {
	if len(p) < 2 {
		return 0, ""
	}
	return ErrCode(binary.BigEndian.Uint16(p[:2])), string(p[2:])
}

// EncodeRegister REGISTER Payload：port(2B) + targetLen(2B) + target + instance(8B)
func EncodeRegister(port uint16, target string, instance [8]byte) []byte {
	b := make([]byte, 2, 4+len(target)+8)
	binary.BigEndian.PutUint16(b, port)
	b = binary.BigEndian.AppendUint16(b, uint16(len(target)))
	b = append(b, target...)
	return append(b, instance[:]...)
}

// DecodeRegister 解析 REGISTER Payload
func DecodeRegister(p []byte) (port uint16, target string, instance [8]byte, err error) {
	if len(p) < 4+8 {
		return 0, "", instance, fmt.Errorf("REGISTER Payload 过短: %d", len(p))
	}
	port = binary.BigEndian.Uint16(p[:2])
	tl := binary.BigEndian.Uint16(p[2:4])
	if int(4+tl+8) > len(p) {
		return 0, "", instance, fmt.Errorf("REGISTER target 长度非法: %d", tl)
	}
	target = string(p[4 : 4+tl])
	copy(instance[:], p[4+tl:4+tl+8])
	return port, target, instance, nil
}

// EncodeU16 / DecodeU16 单 u16 Payload（REGISTER_OK / UNREGISTER / M2 OPEN）
func EncodeU16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func DecodeU16(p []byte) (uint16, error) {
	if len(p) < 2 {
		return 0, fmt.Errorf("u16 Payload 过短: %d", len(p))
	}
	return binary.BigEndian.Uint16(p), nil
}

// EncodeOpenM1 M1 的 OPEN Payload：port(2B) + token(32B)
func EncodeOpenM1(port uint16, token [32]byte) []byte {
	b := make([]byte, 2, 34)
	binary.BigEndian.PutUint16(b, port)
	return append(b, token[:]...)
}

// DecodeOpenM1 解析 M1 OPEN Payload
func DecodeOpenM1(p []byte) (port uint16, token [32]byte, err error) {
	if len(p) < 34 {
		return 0, token, fmt.Errorf("OPEN(M1) Payload 过短: %d", len(p))
	}
	port = binary.BigEndian.Uint16(p[:2])
	copy(token[:], p[2:34])
	return port, token, nil
}

// EncodeCredit CREDIT Payload：delta(4B)
func EncodeCredit(delta uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, delta)
	return b
}

// DecodeCredit 解析 CREDIT Payload
func DecodeCredit(p []byte) (uint32, error) {
	if len(p) < 4 {
		return 0, fmt.Errorf("CREDIT Payload 过短: %d", len(p))
	}
	return binary.BigEndian.Uint32(p), nil
}
