//go:build linux

// yard-node owns one host's agent VMs (internal/node): yard-ctl's executor talks to it over a Unix socket.
//
//	yard-node -root /work/platform/agent-node/allocs -sock /work/platform/agent-node/node.sock
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"yard/internal/node"
)

func main() {
	root := flag.String("root", "/work/platform/agent-node/allocs", "one directory per allocation")
	sock := flag.String("sock", "/work/platform/agent-node/node.sock", "the API's Unix socket")
	fc := flag.String("firecracker", "/work/platform/firecracker/bin/firecracker", "firecracker binary")
	outCap := flag.Int64("output-cap", 64<<20, "bytes of harness output a VM may return")
	flag.Parse()
	logf := log.New(os.Stderr, "yard-node ", log.LstdFlags|log.Lmicroseconds).Printf
	n, err := node.New(*root, &node.Firecracker{Bin: *fc, OutputCap: *outCap, Logf: logf})
	if err != nil {
		log.Fatal(err)
	}
	n.Logf = logf
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	logf("serving %s (allocations in %s)", *sock, *root)
	if err := n.Serve(ctx, *sock); err != nil {
		log.Fatal(err)
	}
}
