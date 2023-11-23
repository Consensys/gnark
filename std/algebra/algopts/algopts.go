package algopts

import "fmt"

type algebraCfg struct {
	NbScalarBits int
}

type AlgebraOption func(*algebraCfg) error

func WithNbBits(bits int) AlgebraOption {
	return func(ac *algebraCfg) error {
		if ac.NbScalarBits != 0 {
			return fmt.Errorf("WithNbBits already set")
		}
		ac.NbScalarBits = bits
		return nil
	}
}

func NewConfig(opts ...AlgebraOption) (*algebraCfg, error) {
	ret := new(algebraCfg)
	for i := range opts {
		if err := opts[i](ret); err != nil {
			return nil, err
		}
	}
	return ret, nil
}
