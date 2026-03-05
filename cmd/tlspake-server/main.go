package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"kemowbench/tlspake"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9443", "listen address")
	ctxStr := flag.String("ctx", "tls13-pq-pake", "base transcript context")
	flag.Parse()

	server, err := tlspake.StartServer(*addr, []byte(*ctxStr))
	if err != nil {
		panic(err)
	}
	defer server.Close()

	fmt.Printf("tlspake server listening on %s\n", server.Addr())
	fmt.Println("press Ctrl+C to stop")

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for res := range server.Results() {
			if res.Err != nil {
				fmt.Printf("session error: %v\n", res.Err)
				continue
			}
			m := res.Metrics
			fmt.Printf("session ok: init=%s s1=%s s2=%s s3=%s s4=%s total=%s payload(total=%d,online=%d,reg=%d)\n",
				m.Init, m.Stage1, m.Stage2, m.Stage3, m.Stage4, m.Total, m.TotalPayloadBytes, m.OnlineBytes, m.RegistrationBytes)
		}
	}()

	<-done
	fmt.Println("server stopped")
}
