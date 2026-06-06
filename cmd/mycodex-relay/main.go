package main

import (
	"os"

	"github.com/mycodex/mycodex-relay/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
