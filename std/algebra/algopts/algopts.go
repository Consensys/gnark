// Package algopts provides shareable options for modifying algebraic operations.
//
// This package is separate to avoid cyclic imports and sharing the structures
// between interface definition, implementation getters and actual
// implementations.
package algopts

import "fmt"

type algebraCfg struct {
	NbScalarBits int
	FoldMulti    bool
	UseSafe      bool
	UseSafeFor   map[int]struct{}
}

// AlgebraOption allows modifying algebraic operation behaviour.
type AlgebraOption func(*algebraCfg) error

// WithNbScalarBits defines the number bits when doing scalar multiplication.
// May be used when it is known that only bits least significant bits are
// non-zero. Reduces the cost for scalar multiplication. If not set then full
// width of scalars used.
func WithNbScalarBits(bits int) AlgebraOption {
	return func(ac *algebraCfg) error {
		if ac.NbScalarBits != 0 {
			return fmt.Errorf("WithNbBits already set")
		}
		ac.NbScalarBits = bits
		return nil
	}
}

// WithFoldingScalarMul can be used when calling MultiScalarMul. By using this
// option we assume that the scalars are `1, scalar, scalar^2, ...`. We use the
// first element as the scalar to be used as a folding coefficients. By using
// this option we avoid one scalar multiplication and do not need to compute the
// powers of the folding coefficient.
func WithFoldingScalarMul() AlgebraOption {
	return func(ac *algebraCfg) error {
		if ac.FoldMulti {
			return fmt.Errorf("withFoldingScalarMul already set")
		}
		ac.FoldMulti = true
		return nil
	}
}

// WithUseSafe forces the use of safe addition formulas for scalar
// multiplication.
func WithUseSafe() AlgebraOption {
	return func(ac *algebraCfg) error {
		if ac.UseSafe {
			return fmt.Errorf("WithUseSafe already set")
		}
		ac.UseSafe = true
		return nil
	}
}

func WithUseSafeFor(idx int) AlgebraOption {
	return func(ac *algebraCfg) error {
		if _, ok := ac.UseSafeFor[idx]; ok {
			return fmt.Errorf("WithUseSafeFor already set for index %d", idx)
		}
		ac.UseSafeFor[idx] = struct{}{}
		return nil
	}
}

// NewConfig applies all given options and returns a configuration to be used.
func NewConfig(opts ...AlgebraOption) (*algebraCfg, error) {
	ret := &algebraCfg{
		UseSafeFor: make(map[int]struct{}),
	}
	for i := range opts {
		if err := opts[i](ret); err != nil {
			return nil, err
		}
	}
	return ret, nil
}
