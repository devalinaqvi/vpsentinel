package report

import (
	"encoding/json"
	"io"

	"github.com/devalinaqvi/vpsentinel/internal/scan"
)

// JSON writes the scan result to w as indented JSON.
func JSON(w io.Writer, r scan.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
