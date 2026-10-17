// Package transport 提供载体（TCP / WebSocket）+ 可选 TLS（SPKI pinning）+ 帧化连接。
package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Cypewake/ghostpipe/internal/protocol"
)

// Conn 帧化连接：串行化写入 + 跟踪最近收帧时间（心跳活性判定用，设计文档 §6）。
type Conn struct {
	rwc      net.Conn
	ver      byte
	wmu      sync.Mutex
	lastRecv atomic.Int64
	closed   atomic.Bool
	closeCh  chan struct{}
}

// NewConn 包装底层连接为帧化连接
func NewConn(rwc net.Conn, ver byte) *Conn {
	return &Conn{rwc: rwc, ver: ver, closeCh: make(chan struct{})}
}

// Send 串行化发送一帧（多 goroutine 安全）
func (c *Conn) Send(t protocol.FrameType, sid uint32, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return protocol.WriteFrame(c.rwc, c.ver, t, sid, payload)
}

// Receive 读取一帧并更新活性时间戳
func (c *Conn) Receive() (*protocol.Frame, error) {
	f, err := protocol.ReadFrame(c.rwc, c.ver)
	if err == nil {
		c.lastRecv.Store(time.Now().UnixMilli())
	}
	return f, err
}

// Raw 底层 net.Conn（设置握手 deadline 用）
func (c *Conn) Raw() net.Conn { return c.rwc }

// LastRecv 最近一次成功收帧的时间
func (c *Conn) LastRecv() time.Time { return time.UnixMilli(c.lastRecv.Load()) }

// Close 关闭连接（幂等）
func (c *Conn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.closeCh)
	}
	return c.rwc.Close()
}

// Done 连接关闭信号
func (c *Conn) Done() <-chan struct{} { return c.closeCh }

// ---- TLS 自签证书与 SPKI pinning（设计文档 §4.2）----

// GenerateSelfSigned 生成内存自签 ECDSA P-256 证书，返回证书与 SPKI-SHA256 指纹（hex）。
func GenerateSelfSigned() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ghostpipe"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	fp, err := SPKIFingerprint(der)
	return cert, fp, err
}

// SPKIFingerprint 计算证书 SPKI（SubjectPublicKeyInfo）的 SHA256 hex 指纹
func SPKIFingerprint(der []byte) (string, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:]), nil
}

// NormalizeFingerprint 去冒号转小写，兼容 xx:yy:zz 与纯 hex 两种写法
func NormalizeFingerprint(fp string) string {
	return strings.ToLower(strings.ReplaceAll(fp, ":", ""))
}

// ---- 客户端拨号 ----

// DialOptions 客户端拨号选项
type DialOptions struct {
	UseTLS      bool          // TLS 1.3（默认开启；显式关闭需应用层打印警告）
	Fingerprint string        // 服务端 SPKI 指纹（TLS 模式必填，无 pin 拒连——设计文档 §4.2）
	WS          bool          // WebSocket 载体（M3）
	WSPath      string        // 默认 /ghostpipe
	Timeout     time.Duration // 默认 10s
}

// Dial 建立"载体 → 可选 TLS"的连接。分层：载体（TCP/WS）在下，TLS 在其上（统一 pinning 路径）。
func Dial(addr string, o DialOptions) (net.Conn, error) {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.WSPath == "" {
		o.WSPath = "/ghostpipe"
	}
	raw, err := net.DialTimeout("tcp", addr, o.Timeout)
	if err != nil {
		return nil, err
	}
	carrier := raw
	if o.WS {
		wsc, err := dialWS(raw, addr, o.WSPath, o.Timeout)
		if err != nil {
			raw.Close()
			return nil, fmt.Errorf("WebSocket 握手失败: %w", err)
		}
		carrier = wsc
	}
	if !o.UseTLS {
		return carrier, nil
	}
	// 设计决策：自签证书 + 自实现 pinning（InsecureSkipVerify 仅关闭系统链校验，
	// 真实校验由 SPKI 指纹比对完成——比盲目跳过校验强）
	tc := tls.Client(carrier, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // 由 SPKI pinning 替代链式校验
		NextProtos:         []string{"github.com/Cypewake/ghostpipe/1"},
	})
	if err := tc.SetDeadline(time.Now().Add(o.Timeout)); err != nil {
		carrier.Close()
		return nil, err
	}
	if err := tc.Handshake(); err != nil {
		carrier.Close()
		return nil, fmt.Errorf("TLS 握手失败: %w", err)
	}
	if err := tc.SetDeadline(time.Time{}); err != nil {
		carrier.Close()
		return nil, err
	}
	if err := verifyPin(tc.ConnectionState(), o.Fingerprint); err != nil {
		carrier.Close()
		return nil, err
	}
	return tc, nil
}

func verifyPin(cs tls.ConnectionState, fp string) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("服务端未提供证书")
	}
	got, err := SPKIFingerprint(cs.PeerCertificates[0].Raw)
	if err != nil {
		return err
	}
	if NormalizeFingerprint(fp) == "" {
		return errors.New("未配置 TLS 指纹，拒绝连接（防中间人，设计文档 §4.2）")
	}
	if got != NormalizeFingerprint(fp) {
		return fmt.Errorf("SPKI 指纹不匹配：期望 %s，实际 %s（疑似中间人）", NormalizeFingerprint(fp), got)
	}
	return nil
}

// ---- 服务端监听 ----

// ListenOptions 服务端监听选项
type ListenOptions struct {
	UseTLS bool
	WS     bool
	Cert   *tls.Certificate // 为空则自动生成自签
}

// Listener 返回已处理载体+TLS 的监听器，Fingerprint 为 TLS 模式下的 SPKI 指纹（供打印）。
type Listener struct {
	net.Listener
	Fingerprint string // 非 TLS 模式为空
}

// Listen 建立"可选 WS 载体 + 可选 TLS"的服务端监听
func Listen(addr string, o ListenOptions) (*Listener, error) {
	var tlsConfig *tls.Config
	var fp string

	if o.UseTLS {
		cert := o.Cert
		f := ""
		var err error
		if cert == nil {
			var c2 tls.Certificate
			c2, f, err = GenerateSelfSigned()
			if err != nil {
				return nil, err
			}
			cert = &c2
		} else if len(cert.Certificate) > 0 {
			f, err = SPKIFingerprint(cert.Certificate[0])
			if err != nil {
				return nil, err
			}
		}
		tlsConfig = &tls.Config{ //nolint:gosec // 自签场景；最低版本 TLS1.2
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"github.com/Cypewake/ghostpipe/1"},
			Certificates: []tls.Certificate{*cert},
		}
		fp = f
	}

	base, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	// 分层顺序（与客户端 Dial 严格对称）：TCP → [WS 载体] → [TLS]
	// WS 在外层：升级后的 wsConn 再被 TLS 包裹，两端一致为 carrier→TLS
	serveLn := base
	if o.WS {
		wsl := newDynamicListener()
		go serveWS(serveLn, func(conn net.Conn) { wsl.push(conn) })
		serveLn = wsl
	}
	if tlsConfig != nil {
		serveLn = tls.NewListener(serveLn, tlsConfig)
	}
	return &Listener{Listener: serveLn, Fingerprint: fp}, nil
}
