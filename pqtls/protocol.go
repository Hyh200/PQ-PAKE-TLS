package pqtls

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"kemowbench/kemchcca"
	"kemowbench/kempca"
	"kemowbench/sha3"
)

const (
	NonceSize       = 32
	MasterKeySize   = 32
	FinishedKeySize = 32
)

type ClientHello struct {
	Random []byte
}

type ServerHello struct {
	Random []byte
	CertPK []byte
}

type EncryptedExtensions struct {
	Data []byte
}

type CertificateRequest struct {
	Data []byte
}

type Certificate struct {
	Data []byte
}

type CertificateVerify struct {
	Signature []byte
}

type ClientHelloDone struct {
	CtS []byte
}

type ServerKemCiphertext struct {
	EC []byte
}

type ClientFinished struct {
	CF []byte
}

type ServerFinished struct {
	SF []byte
}

type SessionMetrics struct {
	InitClientDuration       time.Duration
	InitServerDuration       time.Duration
	HandshakeClientDuration  time.Duration
	HandshakeServerDuration  time.Duration
	Stage1ClientDuration     time.Duration
	Stage1ServerDuration     time.Duration
	Stage2ClientDuration     time.Duration
	Stage2ServerDuration     time.Duration
	Stage3ClientDuration     time.Duration
	Stage3ServerDuration     time.Duration
	Stage4ClientDuration     time.Duration
	Stage4ServerDuration     time.Duration
	ClientBytesSent          int
	ClientBytesReceived      int
	ServerBytesSent          int
	ServerBytesReceived      int
	RegistrationBytes        int
	HandshakeOnlineBytes     int
	HandshakeTotalBytes      int
	ClientAllocsPerSession   float64
	ServerAllocsPerSession   float64
	ClientAllocBytesEstimate float64
	ServerAllocBytesEstimate float64
}

type SessionResult struct {
	MasterKey []byte
	Metrics   SessionMetrics
}

type Server struct {
	kemS *kemchcca.MLKEM768CHCCA
	kemC *kempca.PWKyberPKEKEM

	pkS []byte
	skS []byte
	pkC []byte
}

func NewServer(kemS *kemchcca.MLKEM768CHCCA, kemC *kempca.PWKyberPKEKEM) (*Server, error) {
	pkS, skS, err := kemS.KeyGen()
	if err != nil {
		return nil, err
	}
	return &Server{kemS: kemS, kemC: kemC, pkS: pkS, skS: skS}, nil
}

type Client struct {
	kemS *kemchcca.MLKEM768CHCCA
	kemC *kempca.PWKyberPKEKEM
	pw   []byte
}

func NewClient(kemS *kemchcca.MLKEM768CHCCA, kemC *kempca.PWKyberPKEKEM, pw []byte) *Client {
	pwCopy := make([]byte, len(pw))
	copy(pwCopy, pw)
	return &Client{kemS: kemS, kemC: kemC, pw: pwCopy}
}

func RunSession(pw []byte, ctx []byte) (*SessionResult, error) {
	kemS := kemchcca.NewMLKEM768CHCCA()
	kemC := kempca.NewPWKyberPKEKEM()
	server, err := NewServer(kemS, kemC)
	if err != nil {
		return nil, err
	}
	client := NewClient(kemS, kemC, pw)
	return RunSessionWithRoles(client, server, ctx)
}

func RunSessionWithRoles(client *Client, server *Server, ctx []byte) (*SessionResult, error) {
	var metrics SessionMetrics
	metrics.RegistrationBytes = len(server.pkS)

	initClientStart := time.Now()
	pkC, skC, err := client.kemC.DeriveKeyPairFromPassword(client.pw)
	if err != nil {
		return nil, err
	}
	metrics.InitClientDuration = time.Since(initClientStart)

	initServerStart := time.Now()
	server.pkC = make([]byte, len(pkC))
	copy(server.pkC, pkC)
	metrics.InitServerDuration = time.Since(initServerStart)
	metrics.RegistrationBytes += len(pkC)
	metrics.ClientBytesSent += len(pkC)
	metrics.ServerBytesReceived += len(pkC)

	hsClientStart := time.Now()
	hsServerStart := time.Now()

	transcript := newTranscript(ctx)

	stage1ClientStart := time.Now()
	ch, err := newClientHello()
	if err != nil {
		return nil, err
	}
	transcript.append("CH", ch.Random)
	metrics.ClientBytesSent += len(ch.Random)
	metrics.ServerBytesReceived += len(ch.Random)

	sh, err := newServerHello(server.pkS)
	if err != nil {
		return nil, err
	}
	transcript.append("SH", sh.Random, sh.CertPK)
	metrics.ServerBytesSent += len(sh.Random) + len(sh.CertPK)
	metrics.ClientBytesReceived += len(sh.Random) + len(sh.CertPK)

	ctS, ssSClient, err := client.kemS.Encap(sh.CertPK)
	if err != nil {
		return nil, err
	}
	_ = hkdfExpand(ssSClient, nil, transcript.bytes(), MasterKeySize)
	chd := ClientHelloDone{CtS: ctS}
	transcript.append("CHD", chd.CtS)
	metrics.ClientBytesSent += len(chd.CtS)
	metrics.ServerBytesReceived += len(chd.CtS)
	metrics.Stage1ClientDuration = time.Since(stage1ClientStart)

	stage1ServerStart := time.Now()
	ssSServer, err := server.kemS.Decap(server.skS, chd.CtS)
	if err != nil {
		return nil, err
	}
	_ = hkdfExpand(ssSServer, nil, transcript.bytes(), MasterKeySize)
	metrics.Stage1ServerDuration = time.Since(stage1ServerStart)

	stage2ServerStart := time.Now()
	ctC, ssCServer, err := server.kemC.Encap(server.pkC)
	if err != nil {
		return nil, err
	}
	kicServer := hkdfExpand(append(ssSServer, server.pkC...), nil, transcript.bytes(), len(ctC))
	eC := icXor(kicServer, transcript.bytes(), ctC)
	skc := ServerKemCiphertext{EC: eC}
	transcript.append("SKC", skc.EC)
	metrics.ServerBytesSent += len(skc.EC)
	metrics.ClientBytesReceived += len(skc.EC)
	metrics.Stage2ServerDuration = time.Since(stage2ServerStart)

	stage2ClientStart := time.Now()
	kicClient := hkdfExpand(append(ssSClient, pkC...), nil, transcript.bytesWithout("SKC"), len(skc.EC))
	ctCRecovered := icXor(kicClient, transcript.bytesWithout("SKC"), skc.EC)
	ssCClient, err := client.kemC.Decap(skC, ctCRecovered)
	if err != nil {
		return nil, err
	}
	clientMaster := hkdfExpand(append(ssSClient, ssCClient...), nil, transcript.bytes(), MasterKeySize)
	serverMaster := hkdfExpand(append(ssSServer, ssCServer...), nil, transcript.bytes(), MasterKeySize)
	if !hmac.Equal(clientMaster, serverMaster) {
		return nil, errors.New("master key mismatch")
	}
	metrics.Stage2ClientDuration = time.Since(stage2ClientStart)

	stage3ClientStart := time.Now()
	fkC := hkdfExpand(append(ssSClient, ssCClient...), nil, append([]byte("c finished"), transcript.bytes()...), FinishedKeySize)
	cfTag := hmacTag(fkC, transcript.bytes())
	cf := ClientFinished{CF: cfTag}
	transcript.append("CF", cf.CF)
	metrics.ClientBytesSent += len(cf.CF)
	metrics.ServerBytesReceived += len(cf.CF)
	metrics.Stage3ClientDuration = time.Since(stage3ClientStart)

	stage3ServerStart := time.Now()
	fkCServer := hkdfExpand(append(ssSServer, ssCServer...), nil, append([]byte("c finished"), transcript.bytesWithout("CF")...), FinishedKeySize)
	expectCF := hmacTag(fkCServer, transcript.bytesWithout("CF"))
	if !hmac.Equal(expectCF, cf.CF) {
		return nil, errors.New("client finished mismatch")
	}
	metrics.Stage3ServerDuration = time.Since(stage3ServerStart)

	stage4ServerStart := time.Now()
	fkS := hkdfExpand(append(ssSServer, ssCServer...), nil, append([]byte("s finished"), transcript.bytes()...), FinishedKeySize)
	sfTag := hmacTag(fkS, transcript.bytes())
	sf := ServerFinished{SF: sfTag}
	metrics.ServerBytesSent += len(sf.SF)
	metrics.ClientBytesReceived += len(sf.SF)
	metrics.Stage4ServerDuration = time.Since(stage4ServerStart)

	stage4ClientStart := time.Now()
	fkSClient := hkdfExpand(append(ssSClient, ssCClient...), nil, append([]byte("s finished"), transcript.bytes()...), FinishedKeySize)
	expectSF := hmacTag(fkSClient, transcript.bytes())
	if !hmac.Equal(expectSF, sf.SF) {
		return nil, errors.New("server finished mismatch")
	}
	metrics.Stage4ClientDuration = time.Since(stage4ClientStart)

	metrics.HandshakeClientDuration = time.Since(hsClientStart)
	metrics.HandshakeServerDuration = time.Since(hsServerStart)
	metrics.HandshakeOnlineBytes = metrics.ClientBytesSent + metrics.ServerBytesSent
	metrics.HandshakeTotalBytes = metrics.HandshakeOnlineBytes + metrics.RegistrationBytes

	return &SessionResult{
		MasterKey: clientMaster,
		Metrics:   metrics,
	}, nil
}

type transcriptLog struct {
	ctx    []byte
	labels []string
	parts  [][]byte
}

func newTranscript(ctx []byte) *transcriptLog {
	ctxCopy := make([]byte, len(ctx))
	copy(ctxCopy, ctx)
	return &transcriptLog{ctx: ctxCopy}
}

func (t *transcriptLog) append(label string, payloads ...[]byte) {
	t.labels = append(t.labels, label)
	for _, p := range payloads {
		b := make([]byte, len(p))
		copy(b, p)
		t.parts = append(t.parts, encodePart(label, b))
	}
}

func (t *transcriptLog) bytes() []byte {
	out := make([]byte, 0, len(t.ctx)+512)
	out = append(out, t.ctx...)
	for _, p := range t.parts {
		out = append(out, p...)
	}
	return out
}

func (t *transcriptLog) bytesWithout(lastLabel string) []byte {
	out := make([]byte, 0, len(t.ctx)+512)
	out = append(out, t.ctx...)
	for i := 0; i < len(t.parts); i++ {
		part := t.parts[i]
		if i == len(t.parts)-1 && t.labels[len(t.labels)-1] == lastLabel {
			continue
		}
		out = append(out, part...)
	}
	return out
}

func encodePart(label string, payload []byte) []byte {
	out := make([]byte, 0, len(label)+len(payload)+3)
	out = append(out, []byte(label)...)
	out = append(out, 0)
	out = append(out, byte(len(payload)>>8), byte(len(payload)))
	out = append(out, payload...)
	return out
}

func newClientHello() (*ClientHello, error) {
	rc := make([]byte, NonceSize)
	if _, err := rand.Read(rc); err != nil {
		return nil, err
	}
	return &ClientHello{Random: rc}, nil
}

func newServerHello(certPK []byte) (*ServerHello, error) {
	rs := make([]byte, NonceSize)
	if _, err := rand.Read(rs); err != nil {
		return nil, err
	}
	cp := make([]byte, len(certPK))
	copy(cp, certPK)
	return &ServerHello{Random: rs, CertPK: cp}, nil
}

func hkdfExpand(ikm, salt, info []byte, outLen int) []byte {
	r := hkdfNewSHA256(ikm, salt, info)
	out := make([]byte, outLen)
	_, _ = r.Read(out)
	return out
}

type hkdfReader struct {
	prk  []byte
	info []byte
	n    byte
	buf  []byte
}

func hkdfNewSHA256(ikm, salt, info []byte) *hkdfReader {
	var key []byte
	if salt == nil {
		key = make([]byte, sha256.Size)
	} else {
		key = salt
	}
	prk := hmacSHA256(key, ikm)
	return &hkdfReader{prk: prk, info: info, n: 0}
}

func (r *hkdfReader) Read(p []byte) (int, error) {
	written := 0
	prev := []byte(nil)
	for written < len(p) {
		if len(r.buf) == 0 {
			r.n++
			r.buf = hkdfExpandBlock(r.prk, prev, r.info, r.n)
			prev = r.buf
		}
		n := copy(p[written:], r.buf)
		r.buf = r.buf[n:]
		written += n
	}
	return written, nil
}

func hkdfExpandBlock(prk, prev, info []byte, counter byte) []byte {
	m := make([]byte, 0, len(prev)+len(info)+1)
	m = append(m, prev...)
	m = append(m, info...)
	m = append(m, counter)
	return hmacSHA256(prk, m)
}

func hmacSHA256(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

func hmacTag(key []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
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

func (m SessionMetrics) String() string {
	return fmt.Sprintf(
		"init(client=%s,server=%s) handshake(client=%s,server=%s) bytes(reg=%d,online=%d,total=%d)",
		m.InitClientDuration,
		m.InitServerDuration,
		m.HandshakeClientDuration,
		m.HandshakeServerDuration,
		m.RegistrationBytes,
		m.HandshakeOnlineBytes,
		m.HandshakeTotalBytes,
	)
}
