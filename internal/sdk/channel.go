package sdk

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

const (
	maxTrackLength  = 28
	maxBranchLength = 128
)

var (
	channelTrackPattern  = regexp.MustCompile(`^[a-zA-Z0-9](?:[_.-]?[a-zA-Z0-9])*$`)
	channelRisks         = []string{"stable", "candidate", "beta", "edge"}
	channelBranchPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$`)
)

// ValidateChannel applies the channel grammar used by Workshop v0.9.9.
func ValidateChannel(channel string) error {
	parts := strings.Split(channel, "/")
	var track, risk, branch *string
	switch len(parts) {
	case 1:
		if slices.Contains(channelRisks, parts[0]) {
			risk = &parts[0]
		} else {
			track = &parts[0]
		}
	case 2:
		if slices.Contains(channelRisks, parts[0]) {
			risk, branch = &parts[0], &parts[1]
		} else {
			track, risk = &parts[0], &parts[1]
		}
	case 3:
		track, risk, branch = &parts[0], &parts[1], &parts[2]
	default:
		return fmt.Errorf("channel %q has too many components", channel)
	}

	if track != nil && (len(*track) > maxTrackLength || !channelTrackPattern.MatchString(*track) || slices.Contains(channelRisks, *track)) {
		return fmt.Errorf("invalid track %q in channel %q", *track, channel)
	}
	if risk != nil && !slices.Contains(channelRisks, *risk) {
		return fmt.Errorf("invalid risk %q in channel %q", *risk, channel)
	}
	if branch != nil && (len(*branch) > maxBranchLength || !channelBranchPattern.MatchString(*branch) || slices.Contains(channelRisks, *branch)) {
		return fmt.Errorf("invalid branch %q in channel %q", *branch, channel)
	}
	return nil
}
