package buildinfo_test

import (
	"testing"

	"github.com/shizuku198411/Latra/internal/buildinfo"
)

func TestInfoString(t *testing.T) {
	t.Parallel()

	info := buildinfo.Info{
		Version:   "v1.2.3",
		Commit:    "abc1234",
		BuildDate: "2026-11-03T00:00:00Z",
	}

	const want = "latra v1.2.3 (commit: abc1234, built: 2026-11-03T00:00:00Z)"
	if got := info.String(); got != want {
		t.Fatalf("Info.String() = %q, want %q", got, want)
	}
}
