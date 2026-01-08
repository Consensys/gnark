package fieldextension

import (
	"fmt"
	"math/big"
)

type config struct {
	extension []*big.Int
	degree    int
}

// Option allows to configure the extension field at initialization time.
type Option func(*config) error

// WithDegree forces the degree of the extension field. If not set then we
// choose the degree which provides soundness over the native field.
//
// This option is a no-op when the extension is provided with the
// [WithDirectExtension] option.
func WithDegree(degree int) Option {
	return func(c *config) error {
		if degree < 0 {
			return fmt.Errorf("degree must be non-negative")
		}
		c.degree = degree
		return nil
	}
}

// WithDirectExtension sets the extension of the field. The input should be a slice of
// the polynomial coefficients defining the extension in LSB order. The
// coefficient of the highest degree must be 1.
//
// Example, the extension x^3 + 2x^2 + 3x + 1 is represented as
//
//	[1, 3, 2, 1].
//
// This option overrides the [WithDegree] option.
func WithDirectExtension(extension []*big.Int) Option {
	return func(c *config) error {
		if len(extension) == 0 {
			return fmt.Errorf("extension must be non-empty")
		}
		if extension[len(extension)-1].Cmp(bi1) != 0 {
			return fmt.Errorf("last coefficient of the extension must be 1")
		}
		c.extension = extension
		return nil
	}
}

func newConfig(opts ...Option) (*config, error) {
	c := &config{
		degree: -1,
	}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}
