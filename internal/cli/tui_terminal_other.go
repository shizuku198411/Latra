//go:build !linux

package cli

import "errors"

var errNotTerminal = errors.New("TUI is currently supported on Linux only")

func runTerminalExplorer(_ string, _ []tuiSDK) error { return errNotTerminal }
