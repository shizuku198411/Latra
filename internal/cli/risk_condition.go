package cli

import (
	"fmt"
	"html"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/interfaceview"
)

var conditionSyntax = regexp.MustCompile(`^risk(>=|>)([0-9]+|info|low|medium|high|critical)$`)

type riskCondition struct {
	expression string
	minScore   int
	level      string
}

func parseRiskCondition(value string) (*riskCondition, error) {
	bad := fmt.Errorf("invalid --fail-on condition %q; use 'risk>=high', 'risk>=80' or 'risk>90' (score 0..100)", value)
	parts := conditionSyntax.FindStringSubmatch(value)
	if parts == nil {
		return nil, bad
	}
	c := &riskCondition{expression: value}
	if parts[2][0] >= '0' && parts[2][0] <= '9' {
		score, err := strconv.Atoi(parts[2])
		if err != nil || score > 100 {
			return nil, bad
		}
		c.minScore = score
		if parts[1] == ">" {
			c.minScore++
		}
	} else {
		if parts[1] != ">=" {
			return nil, bad
		}
		c.level = parts[2]
	}
	return c, nil
}

func (c *riskCondition) matches(risk finding.ScoredAxis) bool {
	if c.level != "" {
		return finding.LevelRank(risk.Level) >= finding.LevelRank(c.level)
	}
	return risk.Score >= c.minScore
}

func (c *riskCondition) finish(stderr io.Writer, sdks []finding.SDKAssessment, scanErr error) int {
	if c == nil {
		if scanErr != nil {
			fmt.Fprintf(stderr, "latra: %v\n", scanErr)
			return exitError
		}
		return exitOK
	}
	var message strings.Builder
	code := exitOK
	if scanErr != nil {
		fmt.Fprintf(&message, "latra: %s\nCheck scan diagnostics and report output.\n", interfaceview.Safe(scanErr.Error()))
		code = exitError
	} else {
		var matched []finding.SDKAssessment
		for _, item := range sdks {
			if c.matches(item.Risk) {
				matched = append(matched, item)
			}
		}
		if len(matched) == 0 {
			fmt.Fprintf(&message, "Latra: passed (%s); %d SDKs evaluated\n", c.expression, len(sdks))
		} else {
			code = exitError
			fmt.Fprintf(&message, "Latra: review required (%s); %d of %d SDKs matched\n", c.expression, len(matched), len(sdks))
			for _, item := range matched {
				fmt.Fprintf(&message, "  %s  %d/100 (%s)\n", interfaceview.Safe(item.SDK), item.Risk.Score, item.Risk.Level)
			}
			message.WriteString("Open latra explorer to review the SDK's Key Risks and hooks. Record expected behavior with a suppression rule.\n")
		}
	}
	fmt.Fprintln(stderr, strings.Repeat("-", 60))
	fmt.Fprint(stderr, message.String())
	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		if err := appendRiskSummary(path, message.String()); err != nil {
			fmt.Fprintf(stderr, "latra: write Actions summary: %v\n", err)
			return exitError
		}
	}
	return code
}

func appendRiskSummary(path, message string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "\n### Latra scan\n\n<pre>%s</pre>\n", html.EscapeString(strings.TrimSpace(message)))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
