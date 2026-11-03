//go:build linux

package sdk_test

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/shizuku198411/Latra/internal/sdk"
)

func TestReadInventoriesSpecialFilesWithoutReading(t *testing.T) {
	t.Parallel()

	sdkDir := filepath.Join(t.TempDir(), "fixture")
	writeFile(t, filepath.Join(sdkDir, "sdk.yaml"), "name: fixture\n")
	fifo := filepath.Join(sdkDir, "events.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(sdkDir, "service.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	resolved, err := sdk.Read(sdkDir, "fixture", sdk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"events.fifo", "service.sock"} {
		var found bool
		for _, file := range resolved.Files {
			if file.Path == name {
				found = true
				if file.Type != sdk.FileOther || file.Digest != "" {
					t.Errorf("special file %q = %#v, want unread other entry", name, file)
				}
			}
		}
		if !found {
			t.Errorf("special file %q missing from inventory", name)
		}
	}
}

func TestReadRejectsSpecialFileHook(t *testing.T) {
	t.Parallel()

	sdkDir := filepath.Join(t.TempDir(), "fixture")
	writeFile(t, filepath.Join(sdkDir, "sdk.yaml"), "name: fixture\n")
	hook := filepath.Join(sdkDir, "hooks", "setup-base")
	if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(hook, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := sdk.Read(sdkDir, "fixture", sdk.DefaultLimits())
	assertErrorCode(t, err, sdk.CodeInvalidInput)
}
