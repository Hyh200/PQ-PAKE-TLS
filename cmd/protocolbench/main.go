package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"kemowbench/pqtls"
)

type agg struct {
	sum time.Duration
}

func (a *agg) add(d time.Duration) { a.sum += d }
func (a *agg) avg(n int) float64 {
	return float64(a.sum/time.Duration(n)) / float64(time.Microsecond)
}

func main() {
	iters := flag.Int("iters", 2000, "number of sessions for benchmark")
	pwStr := flag.String("pw", "correct horse battery staple", "password for client key derivation")
	ctxStr := flag.String("ctx", "pqtls-transcript", "context/transcript domain")
	outDir := flag.String("out", "out", "output directory")
	flag.Parse()

	ctx := []byte(*ctxStr)
	pw := []byte(*pwStr)

	aInitC := &agg{}
	aInitS := &agg{}
	aHsC := &agg{}
	aHsS := &agg{}
	aS1C := &agg{}
	aS1S := &agg{}
	aS2C := &agg{}
	aS2S := &agg{}
	aS3C := &agg{}
	aS3S := &agg{}
	aS4C := &agg{}
	aS4S := &agg{}

	var regBytes, onlineBytes, totalBytes int
	var cSent, cRecv, sSent, sRecv int

	for i := 0; i < *iters; i++ {
		res, err := pqtls.RunSession(pw, ctx)
		if err != nil {
			panic(err)
		}
		m := res.Metrics
		aInitC.add(m.InitClientDuration)
		aInitS.add(m.InitServerDuration)
		aHsC.add(m.HandshakeClientDuration)
		aHsS.add(m.HandshakeServerDuration)
		aS1C.add(m.Stage1ClientDuration)
		aS1S.add(m.Stage1ServerDuration)
		aS2C.add(m.Stage2ClientDuration)
		aS2S.add(m.Stage2ServerDuration)
		aS3C.add(m.Stage3ClientDuration)
		aS3S.add(m.Stage3ServerDuration)
		aS4C.add(m.Stage4ClientDuration)
		aS4S.add(m.Stage4ServerDuration)

		regBytes = m.RegistrationBytes
		onlineBytes = m.HandshakeOnlineBytes
		totalBytes = m.HandshakeTotalBytes
		cSent = m.ClientBytesSent
		cRecv = m.ClientBytesReceived
		sSent = m.ServerBytesSent
		sRecv = m.ServerBytesReceived
	}

	clientAllocs := testing.AllocsPerRun(200, func() {
		res, err := pqtls.RunSession(pw, ctx)
		if err != nil {
			panic(err)
		}
		_ = res.MasterKey
	})
	serverAllocs := clientAllocs

	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	memRuns := 1000
	for i := 0; i < memRuns; i++ {
		_, err := pqtls.RunSession(pw, ctx)
		if err != nil {
			panic(err)
		}
	}
	runtime.ReadMemStats(&m1)
	allocBytesPerSession := float64(m1.TotalAlloc-m0.TotalAlloc) / float64(memRuns)
	clientAllocBytes := allocBytesPerSession / 2.0
	serverAllocBytes := allocBytesPerSession / 2.0

	fmt.Printf("PQ-PAKE-TLS protocol bench over %d sessions\n", *iters)
	fmt.Printf("Client init: %.3f us | Server init: %.3f us\n", aInitC.avg(*iters), aInitS.avg(*iters))
	fmt.Printf("Client handshake: %.3f us | Server handshake: %.3f us\n", aHsC.avg(*iters), aHsS.avg(*iters))
	fmt.Printf("Stage1 C/S: %.3f / %.3f us\n", aS1C.avg(*iters), aS1S.avg(*iters))
	fmt.Printf("Stage2 C/S: %.3f / %.3f us\n", aS2C.avg(*iters), aS2S.avg(*iters))
	fmt.Printf("Stage3 C/S: %.3f / %.3f us\n", aS3C.avg(*iters), aS3S.avg(*iters))
	fmt.Printf("Stage4 C/S: %.3f / %.3f us\n", aS4C.avg(*iters), aS4S.avg(*iters))
	fmt.Printf("Memory allocs/session (approx): client=%.1f server=%.1f\n", clientAllocs/2.0, serverAllocs/2.0)
	fmt.Printf("Memory bytes/session (approx): client=%.1fB server=%.1fB\n", clientAllocBytes, serverAllocBytes)
	fmt.Printf("Communication bytes: reg=%d online=%d total=%d\n", regBytes, onlineBytes, totalBytes)
	fmt.Printf("Direction bytes: C->S=%d S->C=%d (C recv=%d, S recv=%d)\n", cSent, sSent, cRecv, sRecv)

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		panic(err)
	}

	f, err := os.Create(filepath.Join(*outDir, "protocolbench.csv"))
	if err != nil {
		panic(err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	_ = w.Write([]string{"metric", "value"})
	_ = w.Write([]string{"client_init_us", fmt.Sprintf("%.6f", aInitC.avg(*iters))})
	_ = w.Write([]string{"server_init_us", fmt.Sprintf("%.6f", aInitS.avg(*iters))})
	_ = w.Write([]string{"client_handshake_us", fmt.Sprintf("%.6f", aHsC.avg(*iters))})
	_ = w.Write([]string{"server_handshake_us", fmt.Sprintf("%.6f", aHsS.avg(*iters))})
	_ = w.Write([]string{"stage1_client_us", fmt.Sprintf("%.6f", aS1C.avg(*iters))})
	_ = w.Write([]string{"stage1_server_us", fmt.Sprintf("%.6f", aS1S.avg(*iters))})
	_ = w.Write([]string{"stage2_client_us", fmt.Sprintf("%.6f", aS2C.avg(*iters))})
	_ = w.Write([]string{"stage2_server_us", fmt.Sprintf("%.6f", aS2S.avg(*iters))})
	_ = w.Write([]string{"stage3_client_us", fmt.Sprintf("%.6f", aS3C.avg(*iters))})
	_ = w.Write([]string{"stage3_server_us", fmt.Sprintf("%.6f", aS3S.avg(*iters))})
	_ = w.Write([]string{"stage4_client_us", fmt.Sprintf("%.6f", aS4C.avg(*iters))})
	_ = w.Write([]string{"stage4_server_us", fmt.Sprintf("%.6f", aS4S.avg(*iters))})
	_ = w.Write([]string{"client_allocs_per_session_approx", fmt.Sprintf("%.3f", clientAllocs/2.0)})
	_ = w.Write([]string{"server_allocs_per_session_approx", fmt.Sprintf("%.3f", serverAllocs/2.0)})
	_ = w.Write([]string{"client_alloc_bytes_per_session_approx", fmt.Sprintf("%.3f", clientAllocBytes)})
	_ = w.Write([]string{"server_alloc_bytes_per_session_approx", fmt.Sprintf("%.3f", serverAllocBytes)})
	_ = w.Write([]string{"registration_bytes", fmt.Sprintf("%d", regBytes)})
	_ = w.Write([]string{"online_bytes", fmt.Sprintf("%d", onlineBytes)})
	_ = w.Write([]string{"total_bytes", fmt.Sprintf("%d", totalBytes)})
	_ = w.Write([]string{"client_to_server_bytes", fmt.Sprintf("%d", cSent)})
	_ = w.Write([]string{"server_to_client_bytes", fmt.Sprintf("%d", sSent)})
	w.Flush()
	if err := w.Error(); err != nil {
		panic(err)
	}
}
