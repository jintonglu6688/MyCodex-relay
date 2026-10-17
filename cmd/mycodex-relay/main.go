package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/mycodex/mycodex-relay/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	exitCode := cli.RunWithContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(exitCode)
}
