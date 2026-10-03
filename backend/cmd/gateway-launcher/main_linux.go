//go:build linux

// gateway-launcher is an opt-in root supervisor composition entry point.
// Its configured executable must implement gatewaylauncher's private FD
// bootstrap contract. Stock main.go does not implement that contract.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/gatewaylauncher"
)

func run(args []string) int {
	flags := flag.NewFlagSet("gateway-launcher", flag.ContinueOnError)
	// Parse errors must not echo possibly sensitive engine arguments.
	flags.SetOutput(io.Discard)
	dir := flags.String("protected-dir", "", "fixed root-owned 0700 authority directory")
	origin := flags.String("origin-ref", "", "fixed opaque private origin reference")
	engine := flags.String("engine", "", "absolute root-owned private native executable")
	uid := flags.Uint("engine-uid", 0, "separate non-root engine uid")
	gid := flags.Uint("engine-gid", 0, "separate non-root engine gid")
	readyTimeout := flags.Duration("ready-timeout", 10*time.Second, "bounded local bootstrap wait")
	stopTimeout := flags.Duration("shutdown-timeout", 10*time.Second, "bounded exact-child cancellation wait")
	if flags.Parse(args) != nil || uint64(*uid) > uint64(^uint32(0)) || uint64(*gid) > uint64(^uint32(0)) || *readyTimeout <= 0 || *readyTimeout > time.Minute || *stopTimeout <= 0 || *stopTimeout > time.Minute {
		fmt.Fprintln(os.Stderr, "launcher: invalid supervisor configuration")
		return 2
	}
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSignals()
	l, err := gatewaylauncher.Start(gatewaylauncher.Config{
		Authority:  gatewaylauncher.AuthorityConfig{Directory: *dir, OriginRef: *origin},
		EnginePath: *engine, Args: flags.Args(), EngineUID: uint32(*uid), EngineGID: uint32(*gid),
	})
	if l == nil {
		fmt.Fprintln(os.Stderr, "launcher: startup denied")
		return 1
	}
	shutdown := func() int {
		ctx, cancel := context.WithTimeout(context.Background(), *stopTimeout)
		defer cancel()
		if _, e := l.Shutdown(ctx); e != nil {
			fmt.Fprintln(os.Stderr, "launcher: teardown pending; protected authority retained")
			return 1
		}
		fmt.Fprintln(os.Stderr, "launcher: exact local child teardown recorded")
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "launcher: startup incomplete")
		shutdown()
		return 1
	}
	ctx, cancel := context.WithTimeout(signalCtx, *readyTimeout)
	err = l.AwaitReady(ctx)
	cancel()
	if err != nil {
		if signalCtx.Err() != nil {
			return shutdown()
		}
		fmt.Fprintln(os.Stderr, "launcher: local readiness unproven")
		shutdown()
		return 1
	}
	fmt.Fprintln(os.Stderr, "launcher: private engine ready")
	// The background Wait observes this exact child and persists retirement.
	exit := make(chan error, 1)
	go func() { _, e := l.Wait(context.Background()); exit <- e }()
	select {
	case <-signalCtx.Done():
		return shutdown()
	case e := <-exit:
		if e != nil {
			fmt.Fprintln(os.Stderr, "launcher: local retirement unproven")
			return 1
		}
		fmt.Fprintln(os.Stderr, "launcher: exact local child teardown recorded")
		return 0
	}
}

func main() { os.Exit(run(os.Args[1:])) }
