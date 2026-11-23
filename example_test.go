package portscan_test

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/12-Bodya-12/portscan"
)

func ExampleScanner_Scan() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port

	scanner, err := portscan.New(
		portscan.WithConcurrency(10),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.Ports(port))
	if err != nil {
		panic(err)
	}

	for res := range results {
		fmt.Printf("%s %s\n", res.Host, res.State)
	}
	// Output:
	// 127.0.0.1 open
}
