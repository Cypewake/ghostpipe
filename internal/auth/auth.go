// Package auth 实现双向 PSK HMAC-SHA256 挑战应答认证（设计文档 §4.1）。
//
// 时序（TLS 建立后、任何其他信令前，总时限 10 秒防 slowloris）：
//
//	S→C  AUTH_REQ {nonce_s 16B}
//	C→S  AUTH_RESP{nonce_c 16B, hmac_c = HMAC(PSK,"c"‖nonce_c‖nonce_s)}
//	S→C  AUTH_OK  {hmac_s = HMAC(PSK,"s"‖nonce_c‖nonce_s)}
//
// 双向认证：client 校验 hmac_s（防恶意 server/中间人）；server 校验 hmac_c。
// 防重放：nonce 每次握手新生成（challenge 本身一次性，无 timestamp——第一轮复核 #6 修正）。
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"ghostpipe/internal/protocol"
	"ghostpipe/internal/transport"
)

// HandshakeTimeout 握手总时限（设计文档 §6，防 slowloris）
const HandshakeTimeout = 10 * time.Second

var (
	ErrAuthFailed   = errors.New("认证失败")
	ErrServerUntrusted = errors.New("服务端身份校验失败（疑似恶意 server/中间人）")
)

func hmacPSK(psk []byte, role byte, nonceC, nonceS []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte{role})
	m.Write(nonceC)
	m.Write(nonceS)
	return m.Sum(nil)
}

func rand16() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Client 客户端侧握手。c 为已完成载体/TLS 建立的帧化连接。
func Client(c *transport.Conn, psk []byte) error {
	c.Raw().SetDeadline(time.Now().Add(HandshakeTimeout))
	defer c.Raw().SetDeadline(time.Time{})

	req, err := c.Receive()
	if err != nil {
		return fmt.Errorf("等待 AUTH_REQ 失败: %w", err)
	}
	if req.Type != protocol.TypeAUTHREQ || len(req.Payload) != 16 {
		return fmt.Errorf("%w: 收到 %s 而非 AUTH_REQ", ErrAuthFailed, req.Type)
	}
	nonceS := req.Payload
	nonceC, err := rand16()
	if err != nil {
		return err
	}
	resp := append(append([]byte{}, nonceC...), hmacPSK(psk, 'c', nonceC, nonceS)...)
	if err := c.Send(protocol.TypeAUTHRESP, 0, resp); err != nil {
		return err
	}
	ok, err := c.Receive()
	if err != nil {
		return fmt.Errorf("等待 AUTH_OK 失败: %w", err)
	}
	if ok.Type == protocol.TypeERROR {
		code, msg := protocol.DecodeError(ok.Payload)
		return fmt.Errorf("%w: 服务端拒绝（%s: %s）", ErrAuthFailed, code, msg)
	}
	if ok.Type != protocol.TypeAUTHOK || len(ok.Payload) != 32 {
		return fmt.Errorf("%w: 收到 %s 而非 AUTH_OK", ErrServerUntrusted, ok.Type)
	}
	expect := hmacPSK(psk, 's', nonceC, nonceS)
	if !hmac.Equal(expect, ok.Payload) {
		return ErrServerUntrusted // 对端无法证明自己持有 PSK → 恶意 server/中间人
	}
	return nil
}

// ServerChallenge 服务端第一步：发出挑战。
// 服务端永远先说话——由此消除"服务端窥视首帧 ↔ 客户端等 AUTH_REQ"的互等竞态。
// 返回 nonceS 供 ServerVerify 使用。
func ServerChallenge(c *transport.Conn) ([]byte, error) {
	nonceS, err := rand16()
	if err != nil {
		return nil, err
	}
	if err := c.Send(protocol.TypeAUTHREQ, 0, nonceS); err != nil {
		return nil, err
	}
	return nonceS, nil
}

// ServerVerify 服务端第二步：校验 AUTH_RESP 并回 AUTH_OK（双向认证的服务端证明）。
// resp 为调用方已读取的应答帧（服务端分诊时读出）；传 nil 则从连接读取。
func ServerVerify(c *transport.Conn, psk []byte, nonceS []byte, resp *protocol.Frame) error {
	if resp == nil {
		var err error
		if resp, err = c.Receive(); err != nil {
			return fmt.Errorf("等待 AUTH_RESP 失败: %w", err)
		}
	}
	if resp.Type != protocol.TypeAUTHRESP || len(resp.Payload) != 48 {
		return fmt.Errorf("%w: 收到 %s 而非 AUTH_RESP", ErrAuthFailed, resp.Type)
	}
	nonceC := resp.Payload[:16]
	gotMAC := resp.Payload[16:]
	expect := hmacPSK(psk, 'c', nonceC, nonceS)
	if !hmac.Equal(expect, gotMAC) {
		_ = c.Send(protocol.TypeERROR, 0, protocol.EncodeError(protocol.ErrCodeAuthFailed, "PSK 校验失败"))
		return ErrAuthFailed
	}
	return c.Send(protocol.TypeAUTHOK, 0, hmacPSK(psk, 's', nonceC, nonceS))
}

// Server 组合式握手（供测试与库用）：挑战 + 校验。
func Server(c *transport.Conn, psk []byte) error {
	nonceS, err := ServerChallenge(c)
	if err != nil {
		return err
	}
	return ServerVerify(c, psk, nonceS, nil)
}
