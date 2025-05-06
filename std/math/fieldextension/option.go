package fieldextension

import "fmt"

type config struct {
	extension []int
	degree    int
}

type Option func(*config) error

// WithDegree forces the degree of the extension field. If not set then we
// choose the degree which provides soundness over the native field.
func WithDegree(degree int) Option {
	return func(c *config) error {
		if degree < 0 {
			return fmt.Errorf("degree must be non-negative")
		}
		c.degree = degree
		return nil
	}
}

func WithExtension(extension []int) Option {
	return func(c *config) error {
		if len(extension) == 0 {
			return fmt.Errorf("extension must be non-empty")
		}
		if extension[len(extension)-1] != 1 {
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
