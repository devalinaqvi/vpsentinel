package checks

import (
	"context"

	"github.com/devalinaqvi/vpsentinel/internal/finding"
)

type Check interface {
	ID() string
	Name() string
	Run(ctx context.Context) ([]finding.Finding, error)
}
