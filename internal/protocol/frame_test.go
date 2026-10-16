package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []struct {
		typ     FrameType
		sid     uint32
		payload []byte
	}{
		{TypeAUTHREQ, 0, make([]byte, 16)},
		{TypeDATA, 0x0000FFFF, bytes.Repeat([]byte{0xAB}, MaxPayload)},
		{TypeCREDIT, 7, []byte{0, 0, 1, 0}},
		{TypePING, 0, nil},
		{TypeOPEN, 42, []byte{0x12, 0x34}},
	}
	for i, tc := range cases {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, ProtocolVersion, tc.typ, tc.sid, tc.payload); err != nil {
			t.Fatalf("用例 %d 写帧失败: %v", i, err)
		}
		f, err := ReadFrame(&buf, ProtocolVersion)
		if err != nil {
			t.Fatalf("用例 %d 读帧失败: %v", i, err)
		}
		if f.Type != tc.typ || f.StreamID != tc.sid || !bytes.Equal(f.Payload, tc.payload) {
			t.Fatalf("用例 %d 回读不一致: %+v", i, f)
		}
	}
}

// TestFrameTruncated 半帧/截断：任意前缀都不应 panic，且必须返回错误。
// （Contract A：帧编解码在字节流任意切分下不得错位或崩溃）
func TestFrameTruncated(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5A}, 300)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, ProtocolVersion, TypeDATA, 9, payload); err != nil {
		t.Fatal(err)
	}
	full := buf.Bytes()
	for cut := 0; cut < len(full); cut++ {
		r := bytes.NewReader(full[:cut])
		f, err := ReadFrame(r, ProtocolVersion)
		if err == nil {
			t.Fatalf("截断到 %d 字节却读取成功: %+v", cut, f)
		}
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("截断到 %d 字节：期望 EOF 类错误，实际 %v", cut, err)
		}
	}
}

// TestFrameConcatenated 粘包：一串帧连续写入，逐帧读取必须精确对齐
func TestFrameConcatenated(t *testing.T) {
	var buf bytes.Buffer
	want := []struct {
		sid uint32
		pl  []byte
	}{
		{1, []byte("hello")},
		{2, bytes.Repeat([]byte{0x01}, 1024)},
		{3, nil},
	}
	for _, w := range want {
		if err := WriteFrame(&buf, ProtocolVersion, TypeDATA, w.sid, w.pl); err != nil {
			t.Fatal(err)
		}
	}
	for _, w := range want {
		f, err := ReadFrame(&buf, ProtocolVersion)
		if err != nil {
			t.Fatalf("粘包读取失败: %v", err)
		}
		if f.StreamID != w.sid || !bytes.Equal(f.Payload, w.pl) {
			t.Fatalf("粘包错位: sid=%d len=%d", f.StreamID, len(f.Payload))
		}
	}
}

func TestFrameBadMagic(t *testing.T) {
	h := make([]byte, HeaderSize)
	h[0], h[1] = 0x00, 0x00 // Magic 错误
	_, err := ReadFrame(bytes.NewReader(h), ProtocolVersion)
	if !errors.Is(err, ErrProtoViolation) {
		t.Fatalf("期望协议违规，实际: %v", err)
	}
}

// TestFrameOversizedLength 先校验后分配：超长 Length 直接拒绝
func TestFrameOversizedLength(t *testing.T) {
	h := make([]byte, HeaderSize)
	h[0], h[1] = MagicByte0, MagicByte1
	h[2] = ProtocolVersion
	h[3] = byte(TypeDATA)
	binary.BigEndian.PutUint32(h[9:13], MaxPayload+1) // 仅超上限 1 字节
	_, err := ReadFrame(bytes.NewReader(h), ProtocolVersion)
	if !errors.Is(err, ErrProtoViolation) {
		t.Fatalf("期望协议违规，实际: %v", err)
	}
}

func TestFrameVersionMismatch(t *testing.T) {
	h := make([]byte, HeaderSize)
	h[0], h[1] = MagicByte0, MagicByte1
	h[2] = ProtocolVersion + 9 // 未来版本
	h[3] = byte(TypePING)
	_, err := ReadFrame(bytes.NewReader(h), ProtocolVersion)
	if !errors.Is(err, ErrProtoViolation) {
		t.Fatalf("期望协议违规，实际: %v", err)
	}
}

func TestWriteFrameRejectsOversize(t *testing.T) {
	if err := WriteFrame(io.Discard, ProtocolVersion, TypeDATA, 0, make([]byte, MaxPayload+1)); err == nil {
		t.Fatal("超限 Payload 应被拒绝")
	}
}

func TestPayloadHelpers(t *testing.T) {
	var inst [8]byte
	copy(inst[:], []byte("12345678"))
	p := EncodeRegister(10022, "127.0.0.1:22", inst)
	port, target, got, err := DecodeRegister(p)
	if err != nil || port != 10022 || target != "127.0.0.1:22" || got != inst {
		t.Fatalf("REGISTER 编解码不一致: %v %s", err, target)
	}

	token := [32]byte{9}
	p = EncodeOpenM1(8080, token)
	p2, tk, err := DecodeOpenM1(p)
	if err != nil || p2 != 8080 || tk != token {
		t.Fatalf("OPEN(M1) 编解码不一致: %v", err)
	}

	p = EncodeError(ErrCodeRemoteRefused, "boom")
	code, msg := DecodeError(p)
	if code != ErrCodeRemoteRefused || msg != "boom" {
		t.Fatalf("ERROR 编解码不一致: %v %s", code, msg)
	}

	p = EncodeCredit(4096)
	d, err := DecodeCredit(p)
	if err != nil || d != 4096 {
		t.Fatalf("CREDIT 编解码不一致: %v", err)
	}
}
