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
	case "help":
		fmt.Fprintln(stdout, "commands: help, version, configure, serve, tenant")
		return 0
	case "version":
		fmt.Fprintf(stdout, "mycodex-relay %s\n", Version)
		return 0
	case "configure":
		fmt.Fprintln(stdout, "configure command will create relay-config.json")
		return 0
	case "serve":
		fmt.Fprintln(stdout, "serve command will start the relay server")
		return 0
	case "tenant":
		fmt.Fprintln(stdout, "tenant commands: create, list, show, disable, enable, rotate-secret, print-connection")
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		return 2
	}
}
