//go:build linux

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/shizuku198411/Latra/internal/report"
	"github.com/shizuku198411/Latra/internal/source"
)

var errNotTerminal = errors.New("not an interactive terminal")

func ioctlTermios(fd uintptr, request uintptr, term *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, uintptr(unsafe.Pointer(term)))
	if errno != 0 {
		return errno
	}
	return nil
}

func runTerminalExplorer(project string, entries []tuiSDK, resolver source.StoreResolver) error {
	// /dev/tty keeps the UI off redirected stdout/stderr and is both readable and writable.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errNotTerminal
	}
	defer tty.Close()
	fd := tty.Fd()
	var original syscall.Termios
	if err := ioctlTermios(fd, syscall.TCGETS, &original); err != nil {
		return errNotTerminal
	}
	raw := original
	raw.Iflag &^= syscall.BRKINT | syscall.ICRNL | syscall.INPCK | syscall.ISTRIP | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.IEXTEN | syscall.ISIG
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	if err := ioctlTermios(fd, syscall.TCSETS, &raw); err != nil {
		return err
	}
	defer ioctlTermios(fd, syscall.TCSETS, &original)
	fmt.Fprint(tty, "\x1b[?1049h\x1b[?25l")
	defer fmt.Fprint(tty, "\x1b[?25h\x1b[?1049l")
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGWINCH)
	defer signal.Stop(signals)
	reader := bufio.NewReader(tty)
	model := tuiExplorer{SDKs: entries}
	type scanOutcome struct {
		document *report.Document
		err      error
	}
	scanDone := make(chan scanOutcome, 1)
	draw := func() {
		var size struct{ Row, Col, X, Y uint16 }
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&size)))
		height, width := int(size.Row), int(size.Col)
		if errno != 0 || height == 0 || width == 0 {
			height, width = 24, 80
		}
		var b strings.Builder
		b.WriteString("\x1b[H\x1b[2J\x1b[1;36m Latra / SDK Explorer\x1b[0m\r\n")
		fmt.Fprintf(&b, " Project: %s\r\n", fitLine(project, width-10))
		if model.Preview != nil {
			fmt.Fprintf(&b, " File: %s  (read-only preview)\r\n", fitLine(model.Preview.Path, width-10))
		} else if model.InTree {
			fmt.Fprintf(&b, " SDK: %s  (read-only tree)\r\n", model.SDKs[model.SelectedSDK].Name)
		} else {
			fmt.Fprintf(&b, " SDKs: %d  (read-only, auto-fetch missing SDKs)\r\n", len(entries))
		}
		b.WriteString(" " + strings.Repeat("─", max(0, min(width-2, 100))) + "\r\n")
		available := max(1, height-7)
		selected, count := model.SelectedSDK, len(entries)
		if model.Preview != nil {
			selected, count = model.Preview.Scroll, len(model.Preview.Lines)
		} else if model.InTree {
			selected, count = model.SelectedNode, len(model.Nodes)
		}
		start := 0
		if model.Preview != nil {
			start = selected
		} else if selected >= available {
			start = selected - available + 1
		}
		if model.Preview != nil {
			annotations := risksForPreview(model.Scan, entries[model.SelectedSDK].Name, model.Preview.Path)
			for _, line := range tuiPreviewRows(model.Preview, annotations, width, available) {
				b.WriteString(line + "\r\n")
			}
		}
		var treeRisks map[string]string
		if model.InTree {
			treeRisks = tuiTreeRisks(model.Scan, entries[model.SelectedSDK].Name)
		}
		for i := start; model.Preview == nil && i < count && i < start+available; i++ {
			var line string
			if model.Preview != nil {
				line = " " + model.Preview.Lines[i]
			} else if model.InTree {
				n := model.Nodes[i]
				symbol := "  "
				if n.Header {
					line = " " + n.Name
				} else if n.Symlink {
					symbol = "@ "
				} else if n.Directory && n.Expanded {
					symbol = "▾ "
				} else if n.Directory {
					symbol = "▸ "
				}
				if !n.Header {
					line = "   " + strings.Repeat("  ", n.Depth) + symbol + n.Name
				}
			} else {
				sdk := entries[i]
				line = tuiSDKListLine(sdk, model.Scan, width)
			}
			level := ""
			if model.InTree && !model.Nodes[i].Header {
				level = treeRisks[model.Nodes[i].Path]
			}
			if model.Preview == nil && i == selected {
				line = " ❯ " + strings.TrimPrefix(line, "   ")
				if level == "" {
					b.WriteString("\x1b[7m")
				}
			}
			if level != "" {
				// Fit before ANSI styling to preserve terminal column widths.
				line = fitLine(line, width)
				if i == selected {
					line = report.ColorReviewPrioritySelected(line, level)
				} else {
					line = report.ColorReviewPriority(line, level)
				}
			}
			if model.Preview == nil && !model.InTree {
				b.WriteString(line) // Already fitted before adding ANSI score colors.
			} else {
				if level != "" {
					b.WriteString(line)
				} else {
					b.WriteString(fitLine(line, width))
				}
			}
			b.WriteString("\x1b[0m\r\n")
		}
		if count == 0 {
			if model.Preview != nil {
				b.WriteString(" (empty file)\r\n")
			} else if model.InTree {
				b.WriteString(" (empty SDK directory)\r\n")
			} else {
				b.WriteString(" No SDKs declared in this project\r\n")
			}
		}
		b.WriteString(fmt.Sprintf("\x1b[%d;1H", max(1, height-2)))
		if model.Message != "" {
			b.WriteString(fitLine(" "+model.Message, width) + "\r\n")
		} else if model.Preview != nil {
			b.WriteString(fitLine(" "+model.Preview.Status, width) + "\r\n")
		} else if !model.InTree && len(entries) > 0 {
			b.WriteString(fitLine(" Workshop: "+entries[model.SelectedSDK].Workshops, width) + "\r\n")
		}
		help := " ↑/↓: move    Enter/→: open SDK    ←/Esc: quit"
		if model.Preview != nil {
			help = " ↑/↓: scroll    ←/Esc: file tree    q: quit"
		} else if model.InTree {
			help = " ↑/↓: move    Enter/→: open / toggle    ←/Esc: SDK list    q: quit"
		}
		help += "    s: scan"
		b.WriteString(fitLine(help, width))
		fmt.Fprint(tty, b.String())
	}
	draw()
	for {
		select {
		case outcome := <-scanDone:
			model.finishScan(outcome.document, outcome.err)
			draw()
		case sig := <-signals:
			if sig == syscall.SIGWINCH {
				draw()
				continue
			}
			return nil
		default:
		}
		// Poll so completed scans and resize signals are handled even without input.
		if reader.Buffered() == 0 && !ttyInputReady(fd, 100*time.Millisecond) {
			continue
		}
		key, err := reader.ReadByte()
		if err != nil {
			return err
		}
		move := 0
		switch key {
		case 'q', 3:
			return nil
		case 's':
			if !model.Scanning {
				model.Scanning = true
				model.Message = "Scanning..."
				go func() {
					document, scanErr := scanExplorer(project, resolver)
					scanDone <- scanOutcome{document: document, err: scanErr}
				}()
			}
		case '\r', '\n':
			model.enter()
		case 27:
			// ANSI arrow keys: ESC [ A/B/C/D. A lone Esc also exits.
			if reader.Buffered() == 0 && !ttyInputReady(fd, 80*time.Millisecond) {
				if model.InTree {
					model.back()
					break
				}
				return nil
			}
			next, _ := reader.ReadByte()
			if next != '[' {
				return nil
			}
			direction, _ := reader.ReadByte()
			switch direction {
			case 'A':
				move = -1
			case 'B':
				move = 1
			case 'C':
				model.enter()
			case 'D':
				if model.InTree {
					model.back()
				} else {
					return nil
				}
			}
		}
		model.move(move)
		draw()
	}
}

func fitLine(s string, width int) string {
	if width <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	return string(r[:width-1]) + "…"
}

// ttyInputReady avoids blocking forever when Escape is pressed alone.
func ttyInputReady(fd uintptr, timeout time.Duration) bool {
	var set syscall.FdSet
	index := int(fd / 64)
	if index >= len(set.Bits) {
		return false
	}
	set.Bits[index] |= 1 << (fd % 64)
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	n, err := syscall.Select(int(fd)+1, &set, nil, nil, &tv)
	return err == nil && n > 0
}

// tuiSDKListLine adds a per-SDK priority only when a scan and sufficient
// terminal width are available. ANSI escapes are added after fitting the text.
func tuiSDKListLine(item tuiSDK, document *report.Document, width int) string {
	line := fmt.Sprintf("   %-23s  %-8s %-13s %-15s", item.Name, item.Source, item.Status, item.Channel)
	if document == nil {
		return fitLine(line, width)
	}
	for _, assessment := range document.Assessment.BySDK {
		if assessment.SDK != item.Name {
			continue
		}
		value := fmt.Sprintf("%d/100", assessment.ReviewPriority.Score)
		prefix := "  Review Priority: "
		// Retain a useful SDK name if the terminal is too narrow for both columns.
		if width-len([]rune(prefix))-len(value) < 12 {
			return fitLine(line, width)
		}
		left := fitLine(line, width-len([]rune(prefix))-len(value))
		return left + prefix + report.ColorReviewPriority(value, assessment.ReviewPriority.Level)
	}
	return fitLine(line, width)
}
