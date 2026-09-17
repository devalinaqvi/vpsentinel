package finding

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Severity int

const (
	SeverityNone Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityCritical: "CRITICAL",
	SeverityHigh:     "HIGH",
	SeverityMedium:   "MEDIUM",
	SeverityLow:      "LOW",
	SeverityNone:     "NONE",
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "UNKNOWN"
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	for k, v := range severityNames {
		if strings.EqualFold(v, str) { // case-insensitive match
			*s = k
			return nil
		}
	}
	return fmt.Errorf("unknown severity: %s", str)
}

type Finding struct {
	RuleID      string            `json:"rule_id"`
	Check       string            `json:"check"`
	Title       string            `json:"title"`
	Severity    Severity          `json:"severity"`
	Resource    string            `json:"resource,omitempty"`
	Description string            `json:"description,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	Confidence  string            `json:"confidence,omitempty"`
	Evidence    map[string]string `json:"evidence,omitempty"`
}
