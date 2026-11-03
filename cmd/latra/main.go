// Command latra provides static analysis for Canonical Workshop SDKs.
package main

import (
	"os"

	"github.com/shizuku198411/Latra/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
