package tlspake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"runtime"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"

	"kemowbench/kemchcca"
	"kemowbench/kempca"
	"kemowbench/sha3"
)

const (
	msgRegisterPKC     byte = 1
	msgClientHello     byte = 2
	msgServerHello     byte = 3
	msgClientHelloDone byte = 4
	msgServerKemCipher byte = 5
	msgClientFinished  byte = 6
	msgServerFinished  byte = 7
)

type CountingConn struct {
	net.Conn
	readBytes  atomic.Int64
	writeBytes atomic.Int64
}

func (c *CountingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.readBytes.Add(int64(n))
	}
	return n, err
}

func (c *CountingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.writeBytes.Add(int64(n))
	}
	return n, err
}

type RoleMetrics struct {
	Init   time.Duration
	Stage1 time.Duration
	Stage2 time.Duration
	Stage3 time.Duration
	Stage4 time.Duration
	Total  time.Duration

	PayloadSent int
	PayloadRecv int
	RawSent     int64
	RawRecv     int64

	RegistrationBytes int
	OnlineBytes       int
	TotalPayloadBytes int

	AllocBytes uint64
	Mallocs    uint64
}

type ServerResult struct {
	Metrics RoleMetrics
	Err     error
}

type Server struct {
	ln      net.Listener
	kemS    *kemchcca.MLKEM768CHCCA
	kemC    *kempca.PWKyberPKEKEM
	baseCtx []byte
	results chan ServerResult
}

func StartServer(addr string, baseCtx []byte) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{
		ln:      ln,
		kemS:    kemchcca.NewMLKEM768CHCCA(),
		kemC:    kempca.NewPWKyberPKEKEM(),
		baseCtx: append([]byte(nil), baseCtx...),
		results: make(chan ServerResult, 1024),
	}
	go s.serve()
	return s, nil
}

func (s *Server) Results() <-chan ServerResult {
	return s.results
}

func (s *Server) Addr() string {
	return s.ln.Addr().String()
}

func (s *Server) Close() error {
	return s.ln.Close()
}

func (s *Server) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(raw net.Conn) {
	cc := &CountingConn{Conn: raw}
	var m RoleMetrics
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	startTotal := time.Now()
	tr := newTranscript(s.baseCtx)

	initStart := time.Now()
	tp, pkCPayload, err := readFrame(cc)
	if err != nil {
		_ = cc.Close()
		s.results <- ServerResult{Err: err}
		return
	}
	if tp != msgRegisterPKC {
		_ = cc.Close()
		s.results <- ServerResult{Err: fmt.Errorf("expect register frame, got type=%d", tp)}
		return
	}
	pkC := append([]byte(nil), pkCPayload...)
	m.PayloadRecv += frameWireLen(pkCPayload)
	m.RegistrationBytes = frameWireLen(pkCPayload)
	m.Init = time.Since(initStart)

	stage1Start := time.Now()
	tp, chPayload, err := readFrame(cc)
	if err != nil {
		_ = cc.Close()
		s.results <- ServerResult{Err: err}
		return
	}
	if tp != msgClientHello || len(chPayload) != 32 {
		_ = cc.Close()
		s.results <- ServerResult{Err: fmt.Errorf("bad client hello")}
		return
	}
	tr.append("CH", chPayload)
	m.PayloadRecv += frameWireLen(chPayload)

	pkS, skS, err := s.kemS.KeyGen()
	if err != nil {
		_ = cc.Close()
		s.results <- ServerResult{Err: err}
		return
	}
	rs := make([]byte, 32)
	if _, err := rand.Read(rs); err != nil {
		_ = cc.Close()
		s.results <- ServerResult{Err: err}
		return
	}
	shPayload := append(rs, pkS...)
	if err := writeFrame(cc, msgServerHello, shPayload); err != nil {
		_ = cc.Close()
		s.results <- ServerResult{Err: err}
		return
	}
	tr.append("SH", shPayload)
	m.PayloadSent += frameWireLen(shPayload)

	tp, chdPayload, err := readFrame(cc)
	if err != nil {
		_ = cc.Close()
		s.results <- ServerResult{Err: err}
		return
	}
	if tp != msgClientHelloDone {
		_ = cc.Close()
		s.results <- ServerResult{Err: fmt.Errorf("expect CHD, got type=%d", tp)}
		return
	}
	tr.append("CHD", chdPayload)
	m.PayloadRecv += frameWireLen(chdPayload)

	ssS, err := s.kemS.Decap(skS, chdPayload)
	if err != nil {
		_ = cc.Close()
		s.results <- ServerResult{Err: err}
		return
	}
	_ = hkdfExpand(ssS, tr.bytes(), 32)
	m.Stage1 = time.Since(stage1Start)

	stage2Start := time.Now()
	ctC, ssC, err := s.kemC.Encap(pkC)
	if err != nil {
		_ = cc.Close()
		s.results <- ServerResult{Err: err}
		return
	}
	kic := hkdfExpand(append(ssS, pkC...), tr.bytes(), len(ctC))
	eC := icXor(kic, tr.bytes(), ctC)
	if err := writeFrame(cc, msgServerKemCipher, eC); err != nil {
		_ = cc.Close()
		s.results <- ServerResult{Err: err}
		return
	}
	tr.append("SKC", eC)
	_ = hkdfExpand(append(ssS, ssC...), tr.bytes(), 32)
	m.PayloadSent += frameWireLen(eC)
	m.Stage2 = time.Since(stage2Start)

	stage3Start := time.Now()
	tp, cfPayload, err := readFrame(cc)
	if err != nil {
		_ = cc.Close()
		s.results <- ServerResult{Err: err}
		return
	}
	if tp != msgClientFinished {
		_ = cc.Close()
		s.results <- ServerResult{Err: fmt.Errorf("expect ClientFinished, got type=%d", tp)}
		return
	}
	fkC := hkdfExpand(append(ssS, ssC...), append([]byte("c finished"), tr.bytes()...), 32)
	expectCF := hmacTag(fkC, tr.bytes())
	if !hmac.Equal(expectCF, cfPayload) {
		_ = cc.Close()
		s.results <- ServerResult{Err: errors.New("client finished mismatch")}
		return
	}
	tr.append("CF", cfPayload)
	m.PayloadRecv += frameWireLen(cfPayload)
	m.Stage3 = time.Since(stage3Start)

	stage4Start := time.Now()
	fkS := hkdfExpand(append(ssS, ssC...), append([]byte("s finished"), tr.bytes()...), 32)
	sf := hmacTag(fkS, tr.bytes())
	if err := writeFrame(cc, msgServerFinished, sf); err != nil {
		_ = cc.Close()
		s.results <- ServerResult{Err: err}
		return
	}
	m.PayloadSent += frameWireLen(sf)
	m.Stage4 = time.Since(stage4Start)

	m.Total = time.Since(startTotal)
	_ = cc.Close()
	m.RawSent = cc.writeBytes.Load()
	m.RawRecv = cc.readBytes.Load()
	m.TotalPayloadBytes = m.PayloadRecv + m.PayloadSent
	m.OnlineBytes = m.TotalPayloadBytes - m.RegistrationBytes
	runtime.ReadMemStats(&after)
	m.AllocBytes = after.TotalAlloc - before.TotalAlloc
	m.Mallocs = after.Mallocs - before.Mallocs
	s.results <- ServerResult{Metrics: m, Err: nil}
}

func RunClientSession(addr string, pw, baseCtx []byte, tamperClientFinished bool) (RoleMetrics, error) {
	var m RoleMetrics
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	startTotal := time.Now()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return m, err
	}
	cc := &CountingConn{Conn: raw}
	tr := newTranscript(baseCtx)

	kemS := kemchcca.NewMLKEM768CHCCA()
	kemC := kempca.NewPWKyberPKEKEM()

	initStart := time.Now()
	pkC, skC, err := kemC.DeriveKeyPairFromPassword(pw)
	if err != nil {
		_ = cc.Close()
		return m, err
	}
	if err := writeFrame(cc, msgRegisterPKC, pkC); err != nil {
		_ = cc.Close()
		return m, err
	}
	m.PayloadSent += frameWireLen(pkC)
	m.RegistrationBytes = frameWireLen(pkC)
	m.Init = time.Since(initStart)

	stage1Start := time.Now()
	rc := make([]byte, 32)
	if _, err := rand.Read(rc); err != nil {
		_ = cc.Close()
		return m, err
	}
	if err := writeFrame(cc, msgClientHello, rc); err != nil {
		_ = cc.Close()
		return m, err
	}
	tr.append("CH", rc)
	m.PayloadSent += frameWireLen(rc)

	tp, shPayload, err := readFrame(cc)
	if err != nil {
		_ = cc.Close()
		return m, err
	}
	if tp != msgServerHello || len(shPayload) <= 32 {
		_ = cc.Close()
		return m, errors.New("bad server hello")
	}
	tr.append("SH", shPayload)
	m.PayloadRecv += frameWireLen(shPayload)

	pkS := shPayload[32:]
	ctS, ssS, err := kemS.Encap(pkS)
	if err != nil {
		_ = cc.Close()
		return m, err
	}
	_ = hkdfExpand(ssS, tr.bytes(), 32)
	if err := writeFrame(cc, msgClientHelloDone, ctS); err != nil {
		_ = cc.Close()
		return m, err
	}
	tr.append("CHD", ctS)
	m.PayloadSent += frameWireLen(ctS)
	m.Stage1 = time.Since(stage1Start)

	stage2Start := time.Now()
	tp, eC, err := readFrame(cc)
	if err != nil {
		_ = cc.Close()
		return m, err
	}
	if tp != msgServerKemCipher {
		_ = cc.Close()
		return m, fmt.Errorf("expect SKC, got %d", tp)
	}
	kic := hkdfExpand(append(ssS, pkC...), tr.bytes(), len(eC))
	ctC := icXor(kic, tr.bytes(), eC)
	ssC, err := kemC.Decap(skC, ctC)
	if err != nil {
		_ = cc.Close()
		return m, err
	}
	tr.append("SKC", eC)
	_ = hkdfExpand(append(ssS, ssC...), tr.bytes(), 32)
	m.PayloadRecv += frameWireLen(eC)
	m.Stage2 = time.Since(stage2Start)

	stage3Start := time.Now()
	fkC := hkdfExpand(append(ssS, ssC...), append([]byte("c finished"), tr.bytes()...), 32)
	cf := hmacTag(fkC, tr.bytes())
	if tamperClientFinished && len(cf) > 0 {
		cf[0] ^= 0x01
	}
	if err := writeFrame(cc, msgClientFinished, cf); err != nil {
		_ = cc.Close()
		return m, err
	}
	tr.append("CF", cf)
	m.PayloadSent += frameWireLen(cf)
	m.Stage3 = time.Since(stage3Start)

	stage4Start := time.Now()
	tp, sf, err := readFrame(cc)
	if err != nil {
		_ = cc.Close()
		return m, err
	}
	if tp != msgServerFinished {
		_ = cc.Close()
		return m, fmt.Errorf("expect SF, got %d", tp)
	}
	fkS := hkdfExpand(append(ssS, ssC...), append([]byte("s finished"), tr.bytes()...), 32)
	expectSF := hmacTag(fkS, tr.bytes())
	if !hmac.Equal(expectSF, sf) {
		_ = cc.Close()
		return m, errors.New("server finished mismatch")
	}
	m.PayloadRecv += frameWireLen(sf)
	m.Stage4 = time.Since(stage4Start)

	m.Total = time.Since(startTotal)
	_ = cc.Close()
	m.RawSent = cc.writeBytes.Load()
	m.RawRecv = cc.readBytes.Load()
	m.TotalPayloadBytes = m.PayloadRecv + m.PayloadSent
	m.OnlineBytes = m.TotalPayloadBytes - m.RegistrationBytes
	runtime.ReadMemStats(&after)
	m.AllocBytes = after.TotalAlloc - before.TotalAlloc
	m.Mallocs = after.Mallocs - before.Mallocs
	return m, nil
}

// Utilities below are retained for baseline TLS1.3 comparison experiments.
func GenerateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func DefaultServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
}

type transcript struct {
	ctx   []byte
	parts [][]byte
}

func newTranscript(ctx []byte) *transcript {
	c := make([]byte, len(ctx))
	copy(c, ctx)
	return &transcript{ctx: c}
}

func (t *transcript) append(label string, payload []byte) {
	p := make([]byte, 0, len(label)+len(payload)+3)
	p = append(p, []byte(label)...)
	p = append(p, 0)
	p = append(p, byte(len(payload)>>8), byte(len(payload)))
	p = append(p, payload...)
	t.parts = append(t.parts, p)
}

func (t *transcript) bytes() []byte {
	out := make([]byte, 0, len(t.ctx)+1024)
	out = append(out, t.ctx...)
	for _, p := range t.parts {
		out = append(out, p...)
	}
	return out
}

func writeFrame(w io.Writer, msgType byte, payload []byte) error {
	h := []byte{msgType, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(h[1:], uint32(len(payload)))
	if _, err := w.Write(h); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func readFrame(r io.Reader) (byte, []byte, error) {
	h := make([]byte, 5)
	if _, err := io.ReadFull(r, h); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n > 10*1024*1024 {
		return 0, nil, fmt.Errorf("frame too large: %d", n)
	}
	p := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, p); err != nil {
			return 0, nil, err
		}
	}
	return h[0], p, nil
}

func frameWireLen(payload []byte) int {
	return 5 + len(payload)
}

func hkdfExpand(ikm, info []byte, n int) []byte {
	r := hkdf.New(sha256.New, ikm, nil, info)
	out := make([]byte, n)
	_, _ = io.ReadFull(r, out)
	return out
}

func hmacTag(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func icXor(key, ctx, in []byte) []byte {
	xof := sha3.NewShake256()
	xof.Write([]byte("ic-v1"))
	xof.Write([]byte{0})
	xof.Write(key)
	xof.Write([]byte{0})
	xof.Write(ctx)
	ks := make([]byte, len(in))
	xof.Read(ks)
	out := make([]byte, len(in))
	for i := range in {
		out[i] = in[i] ^ ks[i]
	}
	return out
}
