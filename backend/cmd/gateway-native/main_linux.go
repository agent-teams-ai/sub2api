//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Wei-Shaw/sub2api/internal/gatewaybootstrap"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "private native bootstrap denied")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if gatewaybootstrap.Run(ctx, gatewaybootstrap.Options{}) != nil {
		fmt.Fprintln(os.Stderr, "private native bootstrap denied")
		os.Exit(1)
	}
}
