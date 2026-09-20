package ports

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/devalinaqvi/vpsentinel/internal/finding"
)

// sensitivePorts maps well-known ports to the service usually behind them.
// Any of these exposed to all interfaces is high-risk.
var sensitivePorts = map[int]string{
	3306:  "MySQL",
	5432:  "PostgreSQL",
	6379:  "Redis",
	27017: "MongoDB",
	9200:  "Elasticsearch",
	11211: "memcached",
	5672:  "RabbitMQ",
}

// Check inspects listening sockets for network-exposure problems.
type Check struct {
	ProcRoot string
}

// New returns a ports Check that reads the real /proc.
func New() *Check {
	return &Check{ProcRoot: "/proc"}
}

func (c *Check) ID() string   { return "ports" }
func (c *Check) Name() string { return "Listening ports" }

func (c *Check) Run(ctx context.Context) ([]finding.Finding, error) {
	procs := buildInodeProcessMap(c.ProcRoot)

	var findings []finding.Finding
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, err := os.ReadFile(filepath.Join(c.ProcRoot, "net", proto))
		if err != nil {
			continue // this protocol file may be absent; skip it
		}
		sockets, err := parseProcNet(proto, data)
		if err != nil {
			continue
		}
		for _, s := range sockets {
			if f, ok := classify(s, procs[s.Inode]); ok {
				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}

// classify turns one socket into a finding (ok=false means ignore it).
func classify(s socket, p procInfo) (finding.Finding, bool) {
	proc := p.Comm
	if proc == "" {
		proc = "unknown"
	}
	resource := fmt.Sprintf("%s/%s:%d (%s)", s.Proto, s.IP, s.Port, proc)
	evidence := map[string]string{
		"protocol": s.Proto,
		"address":  s.IP.String(),
		"port":     strconv.Itoa(s.Port),
		"process":  proc,
		"pid":      p.PID,
	}

	switch {
	case s.IP.IsLoopback():
		return finding.Finding{
			RuleID:      "ports/loopback-listener",
			Check:       "ports",
			Title:       "Listener bound to loopback",
			Severity:    finding.SeverityNone,
			Resource:    resource,
			Description: "Reachable only from the local machine.",
			Confidence:  "high",
			Evidence:    evidence,
		}, true

	case s.IP.IsUnspecified(): // 0.0.0.0 or ::
		if svc, ok := sensitivePorts[s.Port]; ok {
			return finding.Finding{
				RuleID:      "ports/exposed-sensitive-service",
				Check:       "ports",
				Title:       fmt.Sprintf("%s exposed on all interfaces", svc),
				Severity:    finding.SeverityHigh,
				Resource:    resource,
				Description: fmt.Sprintf("%s is listening on all interfaces (%s), so it may be reachable from any network the host is connected to.", svc, s.IP),
				Remediation: fmt.Sprintf("Bind %s to 127.0.0.1, or restrict port %d with a firewall rule.", svc, s.Port),
				Confidence:  "high",
				Evidence:    evidence,
			}, true
		}
		return finding.Finding{
			RuleID:      "ports/public-listener",
			Check:       "ports",
			Title:       "Service listening on all interfaces",
			Severity:    finding.SeverityMedium,
			Resource:    resource,
			Description: fmt.Sprintf("A service is listening on all interfaces (%s) and may be reachable from other networks.", s.IP),
			Remediation: "If it's only needed locally, bind it to 127.0.0.1; otherwise ensure a firewall limits access.",
			Confidence:  "medium",
			Evidence:    evidence,
		}, true

	default: // bound to one specific, non-loopback interface
		return finding.Finding{
			RuleID:      "ports/interface-listener",
			Check:       "ports",
			Title:       "Service listening on a specific interface",
			Severity:    finding.SeverityLow,
			Resource:    resource,
			Description: fmt.Sprintf("A service is bound to %s; exposure depends on whether that interface is public.", s.IP),
			Remediation: "Confirm this interface isn't internet-facing, or firewall the port.",
			Confidence:  "low",
			Evidence:    evidence,
		}, true
	}
}
