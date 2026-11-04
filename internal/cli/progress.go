package cli

import (
	"fmt"
	"io"
	"os"
	"time"
)

const scanProgressLabel = "scanning SDK(s) ..."

type scanProgress struct {
	finish chan bool
	done   chan struct{}
}

func startScanProgress(writer io.Writer, enabled bool) *scanProgress {
	if !enabled {
		return nil
	}
	progress := &scanProgress{finish: make(chan bool), done: make(chan struct{})}
	go func() {
		defer close(progress.done)
		frames := []rune{'|', '/', '-', '\\'}
		frame := 0
		fmt.Fprintf(writer, "%s %c", scanProgressLabel, frames[frame])
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case successful := <-progress.finish:
				status := "failed!"
				if successful {
					status = "completed!"
				}
				fmt.Fprintf(writer, "\r%s %s\n", scanProgressLabel, status)
				return
			case <-ticker.C:
				frame = (frame + 1) % len(frames)
				fmt.Fprintf(writer, "\r%s %c", scanProgressLabel, frames[frame])
			}
		}
	}()
	return progress
}

func (progress *scanProgress) stop(successful bool) {
	if progress == nil {
		return
	}
	progress.finish <- successful
	<-progress.done
}

func isTerminalWriter(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
