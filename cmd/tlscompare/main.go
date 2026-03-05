package main

import (
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"kemowbench/tlspake"
)

type countingConn struct {
	net.Conn
	readBytes  atomic.Int64
	writeBytes atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.readBytes.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.writeBytes.Add(int64(n))
	}
	return n, err
}

type roleMetric struct {
	hs        time.Duration
	total     time.Duration
	rawSent   int64
	rawRecv   int64
	allocB    uint64
	mallocNum uint64
}

type durationAgg struct{ sum time.Duration }
type intAgg struct{ sum int64 }
type uintAgg struct{ sum uint64 }

func (a *durationAgg) add(v time.Duration) { a.sum += v }
func (a *durationAgg) avgUS(n int) float64 {
	return float64(a.sum/time.Duration(n)) / float64(time.Microsecond)
}
func (a *intAgg) add(v int64)       { a.sum += v }
func (a *intAgg) avg(n int) float64 { return float64(a.sum) / float64(n) }
func (a *uintAgg) add(v uint64)     { a.sum += v }
func (a *uintAgg) avg(n int) float64 {
	return float64(a.sum) / float64(n)
}

type pureServer struct {
	ln      net.Listener
	cfg     *tls.Config
	results chan pureResult
}

type pureResult struct {
	m   roleMetric
	err error
}

func startPureServer(addr string, cfg *tls.Config) (*pureServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &pureServer{ln: ln, cfg: cfg, results: make(chan pureResult, 1024)}
	go s.serve()
	return s, nil
}

func (s *pureServer) Addr() string { return s.ln.Addr().String() }
func (s *pureServer) Close() error { return s.ln.Close() }

func (s *pureServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *pureServer) handle(raw net.Conn) {
	cc := &countingConn{Conn: raw}
	var m roleMetric
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	startTotal := time.Now()
	tc := tls.Server(cc, s.cfg)
	hsStart := time.Now()
	if err := tc.Handshake(); err != nil {
		_ = tc.Close()
		runtime.ReadMemStats(&after)
		m.total = time.Since(startTotal)
		m.allocB = after.TotalAlloc - before.TotalAlloc
		m.mallocNum = after.Mallocs - before.Mallocs
		s.results <- pureResult{m: m, err: err}
		return
	}
	m.hs = time.Since(hsStart)

	buf := make([]byte, 4)
	if _, err := io.ReadFull(tc, buf); err != nil {
		_ = tc.Close()
		s.results <- pureResult{err: err}
		return
	}
	if _, err := tc.Write([]byte("pong")); err != nil {
		_ = tc.Close()
		s.results <- pureResult{err: err}
		return
	}
	m.total = time.Since(startTotal)
	_ = tc.Close()

	m.rawSent = cc.writeBytes.Load()
	m.rawRecv = cc.readBytes.Load()
	runtime.ReadMemStats(&after)
	m.allocB = after.TotalAlloc - before.TotalAlloc
	m.mallocNum = after.Mallocs - before.Mallocs
	s.results <- pureResult{m: m, err: nil}
}

func runPureClient(addr string) (roleMetric, error) {
	var m roleMetric
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	startTotal := time.Now()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return m, err
	}
	cc := &countingConn{Conn: raw}
	tc := tls.Client(cc, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		ServerName:         "localhost",
	})
	hsStart := time.Now()
	if err := tc.Handshake(); err != nil {
		_ = tc.Close()
		return m, err
	}
	m.hs = time.Since(hsStart)
	if _, err := tc.Write([]byte("ping")); err != nil {
		_ = tc.Close()
		return m, err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tc, buf); err != nil {
		_ = tc.Close()
		return m, err
	}
	m.total = time.Since(startTotal)
	_ = tc.Close()

	m.rawSent = cc.writeBytes.Load()
	m.rawRecv = cc.readBytes.Load()
	runtime.ReadMemStats(&after)
	m.allocB = after.TotalAlloc - before.TotalAlloc
	m.mallocNum = after.Mallocs - before.Mallocs
	return m, nil
}

func main() {
	iters := flag.Int("iters", 500, "benchmark iterations")
	addr := flag.String("addr", "127.0.0.1:0", "listen address (:0 for auto-free)")
	pwStr := flag.String("pw", "correct horse battery staple", "password for PQ-PAKE-TLS")
	ctxStr := flag.String("ctx", "tls13-pq-pake", "context for PQ-PAKE-TLS")
	outDir := flag.String("out", "out", "output directory")
	flag.Parse()

	cert, err := tlspake.GenerateSelfSignedCert()
	if err != nil {
		panic(err)
	}

	pureServer, err := startPureServer(*addr, tlspake.DefaultServerTLSConfig(cert))
	if err != nil {
		panic(err)
	}
	defer pureServer.Close()
	pureAddr := pureServer.Addr()

	var bCHS, bCTS, bSHS, bSTS durationAgg
	var bCRawS, bSRawS intAgg
	var bCAlloc, bCMalloc, bSAlloc, bSMalloc uintAgg

	for i := 0; i < *iters; i++ {
		cm, err := runPureClient(pureAddr)
		if err != nil {
			panic(fmt.Errorf("baseline client session %d failed: %w", i, err))
		}
		sr := <-pureServer.results
		if sr.err != nil {
			panic(fmt.Errorf("baseline server session %d failed: %w", i, sr.err))
		}
		sm := sr.m

		bCHS.add(cm.hs)
		bCTS.add(cm.total)
		bCRawS.add(cm.rawSent)
		bCAlloc.add(cm.allocB)
		bCMalloc.add(cm.mallocNum)

		bSHS.add(sm.hs)
		bSTS.add(sm.total)
		bSRawS.add(sm.rawSent)
		bSAlloc.add(sm.allocB)
		bSMalloc.add(sm.mallocNum)
	}

	pqServer, err := tlspake.StartServer(*addr, []byte(*ctxStr))
	if err != nil {
		panic(err)
	}
	defer pqServer.Close()
	pqAddr := pqServer.Addr()
	pw := []byte(*pwStr)
	ctx := []byte(*ctxStr)

	var oCTS, oSTS, oCInit, oSInit, oCStage1, oCStage2, oCStage3, oCStage4, oSStage1, oSStage2, oSStage3, oSStage4 durationAgg
	var oCRawS, oSRawS intAgg
	var oCPayloadS, oSPayloadS intAgg
	var oCAlloc, oCMalloc, oSAlloc, oSMalloc uintAgg
	var regB, onlineB, totalB int

	for i := 0; i < *iters; i++ {
		cm, err := tlspake.RunClientSession(pqAddr, pw, ctx, false)
		if err != nil {
			panic(fmt.Errorf("pq client session %d failed: %w", i, err))
		}
		sr := <-pqServer.Results()
		if sr.Err != nil {
			panic(fmt.Errorf("pq server session %d failed: %w", i, sr.Err))
		}
		sm := sr.Metrics

		oCTS.add(cm.Total)
		oCInit.add(cm.Init)
		oCStage1.add(cm.Stage1)
		oCStage2.add(cm.Stage2)
		oCStage3.add(cm.Stage3)
		oCStage4.add(cm.Stage4)
		oCRawS.add(cm.RawSent)
		oCPayloadS.add(int64(cm.PayloadSent))
		oCAlloc.add(cm.AllocBytes)
		oCMalloc.add(cm.Mallocs)

		oSTS.add(sm.Total)
		oSInit.add(sm.Init)
		oSStage1.add(sm.Stage1)
		oSStage2.add(sm.Stage2)
		oSStage3.add(sm.Stage3)
		oSStage4.add(sm.Stage4)
		oSRawS.add(sm.RawSent)
		oSPayloadS.add(int64(sm.PayloadSent))
		oSAlloc.add(sm.AllocBytes)
		oSMalloc.add(sm.Mallocs)

		regB = cm.RegistrationBytes
		onlineB = cm.OnlineBytes
		totalB = cm.TotalPayloadBytes
	}

	clientECDHEs := bCHS.avgUS(*iters) / 1e6
	serverECDHEs := bSHS.avgUS(*iters) / 1e6
	clientOurss := (oCStage1.avgUS(*iters) + oCStage2.avgUS(*iters)) / 1e6
	serverOurss := (oSStage1.avgUS(*iters) + oSStage2.avgUS(*iters)) / 1e6

	clientOursHandshakeUS := oCInit.avgUS(*iters) + oCStage1.avgUS(*iters) + oCStage2.avgUS(*iters) + oCStage3.avgUS(*iters) + oCStage4.avgUS(*iters)
	serverOursHandshakeUS := oSInit.avgUS(*iters) + oSStage1.avgUS(*iters) + oSStage2.avgUS(*iters) + oSStage3.avgUS(*iters) + oSStage4.avgUS(*iters)

	fmt.Printf("Comparison over %d iterations\n", *iters)
	fmt.Println("Shared-key generation time (s):")
	fmt.Printf("  Client: ECDHE_TLS13=%.6f, Ours_PQPAKE_TLS13=%.6f\n", clientECDHEs, clientOurss)
	fmt.Printf("  Server: ECDHE_TLS13=%.6f, Ours_PQPAKE_TLS13=%.6f\n", serverECDHEs, serverOurss)
	fmt.Println("Handshake protocol time (us):")
	fmt.Printf("  Baseline TLS1.3  Client=%.3f Server=%.3f\n", bCHS.avgUS(*iters), bSHS.avgUS(*iters))
	fmt.Printf("  PQ-PAKE-TLS      Client=%.3f Server=%.3f\n", clientOursHandshakeUS, serverOursHandshakeUS)
	fmt.Println("Full-session time (us):")
	fmt.Printf("  Baseline TLS1.3  Client=%.3f Server=%.3f\n", bCTS.avgUS(*iters), bSTS.avgUS(*iters))
	fmt.Printf("  PQ-PAKE-TLS      Client=%.3f Server=%.3f\n", oCTS.avgUS(*iters), oSTS.avgUS(*iters))
	fmt.Println("Raw bytes/session:")
	fmt.Printf("  Baseline TLS1.3  C->S=%.1f S->C=%.1f\n", bCRawS.avg(*iters), bSRawS.avg(*iters))
	fmt.Printf("  PQ-PAKE-TLS      C->S=%.1f S->C=%.1f\n", oCRawS.avg(*iters), oSRawS.avg(*iters))
	fmt.Printf("PQ payload/session: reg=%d online=%d total=%d\n", regB, onlineB, totalB)

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		panic(err)
	}
	csvPath := filepath.Join(*outDir, "tls_compare.csv")
	writeCSV(csvPath, *iters, clientECDHEs, serverECDHEs, clientOurss, serverOurss,
		bCHS.avgUS(*iters), bSHS.avgUS(*iters), clientOursHandshakeUS, serverOursHandshakeUS,
		bCTS.avgUS(*iters), bSTS.avgUS(*iters), oCTS.avgUS(*iters), oSTS.avgUS(*iters),
		bCRawS.avg(*iters), bSRawS.avg(*iters), oCRawS.avg(*iters), oSRawS.avg(*iters),
		oCPayloadS.avg(*iters), oSPayloadS.avg(*iters),
		bCAlloc.avg(*iters), bSAlloc.avg(*iters), oCAlloc.avg(*iters), oSAlloc.avg(*iters),
		bCMalloc.avg(*iters), bSMalloc.avg(*iters), oCMalloc.avg(*iters), oSMalloc.avg(*iters),
		regB, onlineB, totalB)
	texPath := filepath.Join(*outDir, "tls_compare_barplot.tex")
	writeBarplotTEX(texPath, clientECDHEs, serverECDHEs, clientOurss, serverOurss)
	fmt.Printf("Results written to: %s\n", csvPath)
	fmt.Printf("Bar plot (LaTeX) written to: %s\n", texPath)
}

func writeCSV(path string, iters int,
	clientECDHEs, serverECDHEs, clientOurss, serverOurss float64,
	baseCHSUS, baseSHSUS, oursCHSUS, oursSHSUS float64,
	baseCTotalUS, baseSTotalUS, oursCTotalUS, oursSTotalUS float64,
	baseCRawS, baseSRawS, oursCRawS, oursSRawS float64,
	oursCPayloadS, oursSPayloadS float64,
	baseCAlloc, baseSAlloc, oursCAlloc, oursSAlloc float64,
	baseCMalloc, baseSMalloc, oursCMalloc, oursSMalloc float64,
	regB, onlineB, totalB int,
) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"metric", "value"})
	rows := [][2]string{
		{"iters", fmt.Sprintf("%d", iters)},
		{"client_shared_key_time_s_ecdhe_tls13", fmt.Sprintf("%.6f", clientECDHEs)},
		{"client_shared_key_time_s_ours_tls13", fmt.Sprintf("%.6f", clientOurss)},
		{"server_shared_key_time_s_ecdhe_tls13", fmt.Sprintf("%.6f", serverECDHEs)},
		{"server_shared_key_time_s_ours_tls13", fmt.Sprintf("%.6f", serverOurss)},
		{"baseline_client_handshake_us", fmt.Sprintf("%.6f", baseCHSUS)},
		{"baseline_server_handshake_us", fmt.Sprintf("%.6f", baseSHSUS)},
		{"ours_client_handshake_us", fmt.Sprintf("%.6f", oursCHSUS)},
		{"ours_server_handshake_us", fmt.Sprintf("%.6f", oursSHSUS)},
		{"baseline_client_total_us", fmt.Sprintf("%.6f", baseCTotalUS)},
		{"baseline_server_total_us", fmt.Sprintf("%.6f", baseSTotalUS)},
		{"ours_client_total_us", fmt.Sprintf("%.6f", oursCTotalUS)},
		{"ours_server_total_us", fmt.Sprintf("%.6f", oursSTotalUS)},
		{"baseline_raw_c_to_s_bytes", fmt.Sprintf("%.3f", baseCRawS)},
		{"baseline_raw_s_to_c_bytes", fmt.Sprintf("%.3f", baseSRawS)},
		{"ours_raw_c_to_s_bytes", fmt.Sprintf("%.3f", oursCRawS)},
		{"ours_raw_s_to_c_bytes", fmt.Sprintf("%.3f", oursSRawS)},
		{"ours_payload_c_to_s_bytes", fmt.Sprintf("%.3f", oursCPayloadS)},
		{"ours_payload_s_to_c_bytes", fmt.Sprintf("%.3f", oursSPayloadS)},
		{"baseline_client_alloc_bytes", fmt.Sprintf("%.3f", baseCAlloc)},
		{"baseline_server_alloc_bytes", fmt.Sprintf("%.3f", baseSAlloc)},
		{"ours_client_alloc_bytes", fmt.Sprintf("%.3f", oursCAlloc)},
		{"ours_server_alloc_bytes", fmt.Sprintf("%.3f", oursSAlloc)},
		{"baseline_client_mallocs", fmt.Sprintf("%.3f", baseCMalloc)},
		{"baseline_server_mallocs", fmt.Sprintf("%.3f", baseSMalloc)},
		{"ours_client_mallocs", fmt.Sprintf("%.3f", oursCMalloc)},
		{"ours_server_mallocs", fmt.Sprintf("%.3f", oursSMalloc)},
		{"ours_registration_payload_bytes", fmt.Sprintf("%d", regB)},
		{"ours_online_payload_bytes", fmt.Sprintf("%d", onlineB)},
		{"ours_total_payload_bytes", fmt.Sprintf("%d", totalB)},
	}
	for _, r := range rows {
		_ = w.Write([]string{r[0], r[1]})
	}
}

func writeBarplotTEX(path string, clientECDHEs, serverECDHEs, clientOurss, serverOurss float64) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fmt.Fprintln(f, "% Auto-generated by cmd/tlscompare")
	fmt.Fprintln(f, "\\begin{figure}[htb]")
	fmt.Fprintln(f, "\\centering")
	fmt.Fprintln(f, "\\begin{tikzpicture}")
	fmt.Fprintln(f, "\\begin{axis}[")
	fmt.Fprintln(f, "ybar,")
	fmt.Fprintln(f, "bar width=14pt,")
	fmt.Fprintln(f, "width=0.9\\textwidth,")
	fmt.Fprintln(f, "height=6cm,")
	fmt.Fprintln(f, "ylabel={Shared-key generation time (s)},")
	fmt.Fprintln(f, "symbolic x coords={Client,Server},")
	fmt.Fprintln(f, "xtick=data,")
	fmt.Fprintln(f, "legend style={at={(0.5,1.12)},anchor=south,legend columns=-1},")
	fmt.Fprintln(f, "grid=both,")
	fmt.Fprintln(f, "]")
	fmt.Fprintln(f, "\\addplot+[fill=gray!65, draw=black] coordinates {")
	fmt.Fprintf(f, "(Client, %.6f)\n", clientECDHEs)
	fmt.Fprintf(f, "(Server, %.6f)\n", serverECDHEs)
	fmt.Fprintln(f, "};")
	fmt.Fprintln(f, "\\addplot+[fill=gray!20, draw=black] coordinates {")
	fmt.Fprintf(f, "(Client, %.6f)\n", clientOurss)
	fmt.Fprintf(f, "(Server, %.6f)\n", serverOurss)
	fmt.Fprintln(f, "};")
	fmt.Fprintln(f, "\\legend{ECDHE in TLS1.3,Ours in TLS1.3}")
	fmt.Fprintln(f, "\\end{axis}")
	fmt.Fprintln(f, "\\end{tikzpicture}")
	fmt.Fprintln(f, "\\caption{Comparison of shared-key generation time between standard TLS1.3 and PQ-PAKE-TLS.}")
	fmt.Fprintln(f, "\\label{fig:tls-compare-shared-key}")
	fmt.Fprintln(f, "\\end{figure}")
}
