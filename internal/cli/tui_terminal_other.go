//go:build !linux

package cli

import (
	"errors"

	"github.com/shizuku198411/Latra/internal/source"
)

var errNotTerminal = errors.New("TUI is currently supported on Linux only")

func runTerminalExplorer(_ string, _ []tuiSDK, _ source.StoreResolver) error { return errNotTerminal }
