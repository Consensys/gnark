// Package algopts provides shareable options for modifying algebraic operations.
//
// This package is separate to avoid cyclic imports and sharing the structures
// between interface definition, implementation getters and actual
// implementations.
package algopts

import (
	"errors"
)

type algebraCfg struct {
	NbScalarBits       int
	FoldMulti          bool
	CompleteArithmetic bool
	ToBitsCanonical    bool
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
			return errors.New("WithNbBits already set")
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
			return errors.New("withFoldingScalarMul already set")
		}
		ac.FoldMulti = true
		return nil
	}
}

// WithCompleteArithmetic forces the use of safe addition formulas for scalar
// multiplication.
func WithCompleteArithmetic() AlgebraOption {
	return func(ac *algebraCfg) error {
		if ac.CompleteArithmetic {
			return errors.New("WithCompleteArithmetic already set")
		}
		ac.CompleteArithmetic = true
		return nil
	}
}

// WithCanonicalBitRepresentation enforces the marshalling methods to assert
// that the bit representation is in canonical form. For field elements this
// means that the bits represent a number less than the modulus.
//
// This option is useful when performing direct comparison between the bit form
// of two elements. It can be avoided when the bit representation is used in
// other cases, such as computing a challenge using a hash function, where
// non-canonical bit representation leads to incorrect challenge (which in turn
// makes the verification fail).
func WithCanonicalBitRepresentation() AlgebraOption {
	return func(ac *algebraCfg) error {
		if ac.ToBitsCanonical {
			return errors.New("WithCanonicalBitRepresentation already set")
		}
		ac.ToBitsCanonical = true
		return nil
	}
}

// NewConfig applies all given options and returns a configuration to be used.
func NewConfig(opts ...AlgebraOption) (*algebraCfg, error) {
	ret := new(algebraCfg)
	for i := range opts {
		if err := opts[i](ret); err != nil {
			return nil, err
		}
	}
	return ret, nil
}
