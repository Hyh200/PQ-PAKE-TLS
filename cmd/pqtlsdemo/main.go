package main

import (
	"encoding/hex"
	"flag"
	"fmt"

	"kemowbench/pqtls"
)

func main() {
	pwStr := flag.String("pw", "correct horse battery staple", "password for client key derivation")
	ctxStr := flag.String("ctx", "pqtls-transcript", "context/transcript domain")
	flag.Parse()

	res, err := pqtls.RunSession([]byte(*pwStr), []byte(*ctxStr))
	if err != nil {
		panic(err)
	}

	fmt.Println("PQ-PAKE-TLS demo session completed")
	fmt.Printf("MasterKey(32B): %s\n", hex.EncodeToString(res.MasterKey))
	fmt.Printf("Metrics: %s\n", res.Metrics.String())
}
