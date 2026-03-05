package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"kemowbench/tlspake"
)

type durationAgg struct{ sum time.Duration }
type intAgg struct{ sum int64 }

func (a *durationAgg) add(v time.Duration) { a.sum += v }
func (a *durationAgg) avg(n int) float64 {
	return float64(a.sum/time.Duration(n)) / float64(time.Microsecond)
}
func (a *intAgg) add(v int64)       { a.sum += v }
func (a *intAgg) avg(n int) float64 { return float64(a.sum) / float64(n) }

func main() {
	iters := flag.Int("iters", 500, "number of PQ-PAKE-TLS sessions")
	integrityTrials := flag.Int("integrity_trials", 100, "tamper trials for integrity detection")
	addr := flag.String("addr", "127.0.0.1:0", "listen/dial address (use :0 for auto-free port)")
	pwStr := flag.String("pw", "correct horse battery staple", "password")
	ctxStr := flag.String("ctx", "tls13-pq-pake", "base transcript context")
	outDir := flag.String("out", "out", "output dir")
	flag.Parse()

	server, err := tlspake.StartServer(*addr, []byte(*ctxStr))
	if err != nil {
		panic(err)
	}
	defer server.Close()
	runAddr := server.Addr()

	pw := []byte(*pwStr)
	baseCtx := []byte(*ctxStr)

	var cInit, cS1, cS2, cS3, cS4, cTot durationAgg
	var sInit, sS1, sS2, sS3, sS4, sTot durationAgg
	var cPayloadSent, cPayloadRecv, sPayloadSent, sPayloadRecv intAgg
	var cRawSent, cRawRecv, sRawSent, sRawRecv intAgg
	var cAllocBytes, cMallocs, sAllocBytes, sMallocs intAgg
	var regB, onlineB, totalB int

	for i := 0; i < *iters; i++ {
		cm, err := tlspake.RunClientSession(runAddr, pw, baseCtx, false)
		if err != nil {
			panic(fmt.Errorf("client session %d failed: %w", i, err))
		}
		sr := <-server.Results()
		if sr.Err != nil {
			panic(fmt.Errorf("server session %d failed: %w", i, sr.Err))
		}
		sm := sr.Metrics

		cInit.add(cm.Init)
		cS1.add(cm.Stage1)
		cS2.add(cm.Stage2)
		cS3.add(cm.Stage3)
		cS4.add(cm.Stage4)
		cTot.add(cm.Total)
		cPayloadSent.add(int64(cm.PayloadSent))
		cPayloadRecv.add(int64(cm.PayloadRecv))
		cRawSent.add(cm.RawSent)
		cRawRecv.add(cm.RawRecv)
		cAllocBytes.add(int64(cm.AllocBytes))
		cMallocs.add(int64(cm.Mallocs))

		sInit.add(sm.Init)
		sS1.add(sm.Stage1)
		sS2.add(sm.Stage2)
		sS3.add(sm.Stage3)
		sS4.add(sm.Stage4)
		sTot.add(sm.Total)
		sPayloadSent.add(int64(sm.PayloadSent))
		sPayloadRecv.add(int64(sm.PayloadRecv))
		sRawSent.add(sm.RawSent)
		sRawRecv.add(sm.RawRecv)
		sAllocBytes.add(int64(sm.AllocBytes))
		sMallocs.add(int64(sm.Mallocs))

		regB = cm.RegistrationBytes
		onlineB = cm.OnlineBytes
		totalB = cm.TotalPayloadBytes
	}

	fmt.Printf("PQ-PAKE-TLS bench over %d sessions\n", *iters)
	fmt.Printf("Client(us): init=%.3f s1=%.3f s2=%.3f s3=%.3f s4=%.3f total=%.3f\n",
		cInit.avg(*iters), cS1.avg(*iters), cS2.avg(*iters), cS3.avg(*iters), cS4.avg(*iters), cTot.avg(*iters))
	fmt.Printf("Server(us): init=%.3f s1=%.3f s2=%.3f s3=%.3f s4=%.3f total=%.3f\n",
		sInit.avg(*iters), sS1.avg(*iters), sS2.avg(*iters), sS3.avg(*iters), sS4.avg(*iters), sTot.avg(*iters))
	fmt.Printf("Payload bytes/session: C->S=%.1f S->C=%.1f\n", cPayloadSent.avg(*iters), sPayloadSent.avg(*iters))
	fmt.Printf("Raw bytes/session: C->S=%.1f S->C=%.1f\n", cRawSent.avg(*iters), sRawSent.avg(*iters))
	fmt.Printf("Memory/session: client mallocs=%.1f allocBytes=%.1f | server mallocs=%.1f allocBytes=%.1f\n",
		cMallocs.avg(*iters), cAllocBytes.avg(*iters), sMallocs.avg(*iters), sAllocBytes.avg(*iters))
	fmt.Printf("Communication summary(payload): registration=%d online=%d total=%d\n", regB, onlineB, totalB)

	detected := 0
	for i := 0; i < *integrityTrials; i++ {
		_, clientErr := tlspake.RunClientSession(runAddr, pw, baseCtx, true)
		sr := <-server.Results()
		if clientErr != nil || sr.Err != nil {
			detected++
		}
	}
	detectionRate := 0.0
	if *integrityTrials > 0 {
		detectionRate = float64(detected) * 100.0 / float64(*integrityTrials)
	}
	fmt.Printf("Integrity tamper detection: %d/%d (%.2f%%)\n", detected, *integrityTrials, detectionRate)

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		panic(err)
	}
	csvPath := filepath.Join(*outDir, "tlspakebench.csv")
	csvPath = ensureWritableCSVPath(csvPath)
	writeCSV(csvPath, *iters, cInit, cS1, cS2, cS3, cS4, cTot, sInit, sS1, sS2, sS3, sS4, sTot,
		cPayloadSent, cPayloadRecv, sPayloadSent, sPayloadRecv, cRawSent, cRawRecv, sRawSent, sRawRecv,
		cMallocs, cAllocBytes, sMallocs, sAllocBytes, regB, onlineB, totalB, *integrityTrials, detected, detectionRate)
	fmt.Printf("Results written to: %s\n", csvPath)
}

func ensureWritableCSVPath(basePath string) string {
	f, err := os.OpenFile(basePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err == nil {
		_ = f.Close()
		return basePath
	}
	ts := time.Now().Format("20060102_150405")
	dir := filepath.Dir(basePath)
	name := filepath.Base(basePath)
	ext := filepath.Ext(name)
	stem := name[:len(name)-len(ext)]
	return filepath.Join(dir, fmt.Sprintf("%s_%s%s", stem, ts, ext))
}

func writeCSV(path string, iters int,
	cInit, cS1, cS2, cS3, cS4, cTot durationAgg,
	sInit, sS1, sS2, sS3, sS4, sTot durationAgg,
	cPayloadSent, cPayloadRecv, sPayloadSent, sPayloadRecv, cRawSent, cRawRecv, sRawSent, sRawRecv intAgg,
	cMallocs, cAllocBytes, sMallocs, sAllocBytes intAgg,
	regB, onlineB, totalB int,
	integrityTrials, detected int,
	detectionRate float64,
) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()

	rows := [][2]string{
		{"iters", fmt.Sprintf("%d", iters)},
		{"client_init_us", fmt.Sprintf("%.6f", cInit.avg(iters))},
		{"client_stage1_us", fmt.Sprintf("%.6f", cS1.avg(iters))},
		{"client_stage2_us", fmt.Sprintf("%.6f", cS2.avg(iters))},
		{"client_stage3_us", fmt.Sprintf("%.6f", cS3.avg(iters))},
		{"client_stage4_us", fmt.Sprintf("%.6f", cS4.avg(iters))},
		{"client_total_us", fmt.Sprintf("%.6f", cTot.avg(iters))},
		{"server_init_us", fmt.Sprintf("%.6f", sInit.avg(iters))},
		{"server_stage1_us", fmt.Sprintf("%.6f", sS1.avg(iters))},
		{"server_stage2_us", fmt.Sprintf("%.6f", sS2.avg(iters))},
		{"server_stage3_us", fmt.Sprintf("%.6f", sS3.avg(iters))},
		{"server_stage4_us", fmt.Sprintf("%.6f", sS4.avg(iters))},
		{"server_total_us", fmt.Sprintf("%.6f", sTot.avg(iters))},
		{"client_payload_sent_bytes", fmt.Sprintf("%.3f", cPayloadSent.avg(iters))},
		{"client_payload_recv_bytes", fmt.Sprintf("%.3f", cPayloadRecv.avg(iters))},
		{"server_payload_sent_bytes", fmt.Sprintf("%.3f", sPayloadSent.avg(iters))},
		{"server_payload_recv_bytes", fmt.Sprintf("%.3f", sPayloadRecv.avg(iters))},
		{"client_raw_sent_bytes", fmt.Sprintf("%.3f", cRawSent.avg(iters))},
		{"client_raw_recv_bytes", fmt.Sprintf("%.3f", cRawRecv.avg(iters))},
		{"server_raw_sent_bytes", fmt.Sprintf("%.3f", sRawSent.avg(iters))},
		{"server_raw_recv_bytes", fmt.Sprintf("%.3f", sRawRecv.avg(iters))},
		{"client_mallocs", fmt.Sprintf("%.3f", cMallocs.avg(iters))},
		{"client_alloc_bytes", fmt.Sprintf("%.3f", cAllocBytes.avg(iters))},
		{"server_mallocs", fmt.Sprintf("%.3f", sMallocs.avg(iters))},
		{"server_alloc_bytes", fmt.Sprintf("%.3f", sAllocBytes.avg(iters))},
		{"registration_payload_bytes", fmt.Sprintf("%d", regB)},
		{"online_payload_bytes", fmt.Sprintf("%d", onlineB)},
		{"total_payload_bytes", fmt.Sprintf("%d", totalB)},
		{"integrity_trials", fmt.Sprintf("%d", integrityTrials)},
		{"integrity_detected", fmt.Sprintf("%d", detected)},
		{"integrity_detection_rate_pct", fmt.Sprintf("%.2f", detectionRate)},
	}
	_ = w.Write([]string{"metric", "value"})
	for _, r := range rows {
		_ = w.Write([]string{r[0], r[1]})
	}
}
