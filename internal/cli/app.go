package cli

import (
	"fmt"
	"io"
)

const Version = "dev"

func Run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "command required")
		return 2
	}

	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "mycodex-relay %s\n", Version)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		return 2
	}
}
