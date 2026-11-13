package source

import (
	"context"
	"github.com/shizuku198411/Latra/internal/sdk"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigurationRetainsExcludedSystem(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".workshop"), 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte("name: dev\nbase: ubuntu@24.04\nsdks:\n  - name: system\n    slots:\n      key:\n        interface: secret\n        attributes:\n          service: demo\nconnections:\n  - plug: app:key\n    slot: ':key'\n")
	if err := os.WriteFile(filepath.Join(root, ".workshop", "dev.yaml"), data, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := ScanWithResolver(context.Background(), root, sdk.DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SDKs) != 0 || len(result.Configurations) != 1 || len(result.Configurations[0].SDKs) != 1 || len(result.Configurations[0].Connections) != 1 {
		t.Fatalf("result: %+v", result)
	}
}
