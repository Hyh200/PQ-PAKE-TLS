package main

import (
	"flag"
	"fmt"

	"kemowbench/tlspake"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9443", "server address")
	pwStr := flag.String("pw", "correct horse battery staple", "password")
	ctxStr := flag.String("ctx", "tls13-pq-pake", "base transcript context")
	count := flag.Int("n", 1, "number of sessions")
	tamper := flag.Bool("tamper_cf", false, "tamper ClientFinished for integrity test")
	flag.Parse()

	pw := []byte(*pwStr)
	ctx := []byte(*ctxStr)

	ok := 0
	fail := 0
	for i := 0; i < *count; i++ {
		m, err := tlspake.RunClientSession(*addr, pw, ctx, *tamper)
		if err != nil {
			fail++
			fmt.Printf("session[%d] fail: %v\n", i, err)
			continue
		}
		ok++
		fmt.Printf("session[%d] ok: init=%s s1=%s s2=%s s3=%s s4=%s total=%s payload(total=%d,online=%d,reg=%d)\n",
			i, m.Init, m.Stage1, m.Stage2, m.Stage3, m.Stage4, m.Total, m.TotalPayloadBytes, m.OnlineBytes, m.RegistrationBytes)
	}
	fmt.Printf("summary: ok=%d fail=%d\n", ok, fail)
}
