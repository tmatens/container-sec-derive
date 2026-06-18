// Command csd is the container-sec-derive entry point: a thin shim over
// internal/cli. The release pipeline injects the version string here via
// -ldflags "-X github.com/tmatens/container-sec-derive/internal/cli.version=...".
package main

import (
	"fmt"
	"os"

	"github.com/tmatens/container-sec-derive/internal/cli"
	"github.com/tmatens/container-sec-derive/internal/exit"
)

func main() {
	err := cli.Run(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "csd:", err)
	}
	os.Exit(exit.CodeFor(err))
}
