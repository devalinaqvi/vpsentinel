package scan

import (
	"context"
	"os"
	"sort"
	"time"

	"github.com/devalinaqvi/vpsentinel/internal/checks"
	"github.com/devalinaqvi/vpsentinel/internal/finding"
)

type Meta struct {
	Tool     string    `json:"tool"`
	Version  string    `json:"version"`
	Hostname string    `json:"hostname"`
	Time     time.Time `json:"time"`
}

type CheckError struct {
	Check string `json:"check"`
	Error string `json:"error"`
}

type Result struct {
	Meta     Meta              `json:"meta"`
	Findings []finding.Finding `json:"findings"`
	Errors   []CheckError      `json:"errors,omitempty"`
}

func Run(ctx context.Context, version string, cs []checks.Check) Result {
	host, _ := os.Hostname()
	res := Result{Meta: Meta{
		Tool: "vpsentinel", Version: version, Hostname: host, Time: time.Now().UTC(),
	}}
	for _, c := range cs {
		fs, err := c.Run(ctx)
		if err != nil {
			res.Errors = append(res.Errors, CheckError{Check: c.ID(), Error: err.Error()})
			continue
		}
		res.Findings = append(res.Findings, fs...)
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		return res.Findings[i].Severity > res.Findings[j].Severity
	})
	return res
}
