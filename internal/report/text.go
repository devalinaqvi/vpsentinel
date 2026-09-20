package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/devalinaqvi/vpsentinel/internal/finding"
	"github.com/devalinaqvi/vpsentinel/internal/scan"
)

// Text writes a human-readable report to w.
func Text(w io.Writer, r scan.Result) error {
	fmt.Fprintf(w, "%s %s — scan of %s — %s\n\n",
		r.Meta.Tool, r.Meta.Version, r.Meta.Hostname, r.Meta.Time.Format(time.RFC3339))

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "No known issues found.")
	}

	for _, f := range r.Findings {
		fmt.Fprintf(w, "[%s] %s — %s\n", f.Severity, f.Title, f.Resource)
		if f.Remediation != "" {
			fmt.Fprintf(w, "        fix: %s\n", f.Remediation)
		}
	}

	fmt.Fprintf(w, "\n%s\n", summarize(r.Findings))

	if len(r.Errors) > 0 {
		fmt.Fprintln(w, "\nChecks skipped:")
		for _, e := range r.Errors {
			fmt.Fprintf(w, "  - %s: %s\n", e.Check, e.Error)
		}
	}
	return nil
}

// summarize returns a one-line count like "5 findings (1 high, 4 none)".
func summarize(fs []finding.Finding) string {
	counts := map[finding.Severity]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	order := []finding.Severity{
		finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
		finding.SeverityLow, finding.SeverityNone,
	}
	var parts []string
	for _, sev := range order {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[sev], strings.ToLower(sev.String())))
		}
	}
	s := fmt.Sprintf("%d findings", len(fs))
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	return s
}
