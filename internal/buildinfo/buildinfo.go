// Package buildinfo exposes release metadata injected at build time.
package buildinfo

import "fmt"

// These values are overridden with -ldflags for release builds.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Info is the build metadata shown by the version command.
type Info struct {
	Version   string
	Commit    string
	BuildDate string
}

// Current returns the metadata embedded in the running binary.
func Current() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
	}
}

// String returns a stable, human-readable representation of the build metadata.
func (i Info) String() string {
	return fmt.Sprintf("latra %s (commit: %s, built: %s)", i.Version, i.Commit, i.BuildDate)
}
