// Package fieldextension provides operations over an extension field of the native field.
//
// The operations inside the circuit are performed in the native field. In case
// of small fields, we need to perform some operations over an extension field
// to achieve the required soundness level. This package provides some
// primitives to perform such operations.
package fieldextension

import (
	"fmt"
	"strconv"

	"github.com/consensys/gnark/frontend"
)

type extensionType int

const (
	minimal extensionType = iota // x^n + 1
	simple                       // x^n + d
	generic                      // everything else
)

// ext implements the [Field] interface. We have separated the implementation
// and interface to possibly have generic implementation in the future (PLONK
// custom gates).
type ext struct {
	api frontend.API

	extension []int // we expect the extension defining modulus to have small small coefficients
	extensionType
}

// Field is the extension field interface over native field. It provides
// the basic operations over the extension field.
type Field interface {
	// Reduce reduces the extension field element modulo the defining polynomial.
	Reduce(a Element) Element
	// Mul multiplies two extension field elements and reduces the result.
	Mul(a, b Element) Element
	// MulNoReduce multiplies two extension field elements without reducing the result.
	// The degree of the result is the sum of the degrees of the two operands.
	MulNoReduce(a, b Element) Element
	// Add adds two extension field elements. The result is not reduced. The
	// degree of the result is the max of the degrees of the two operands.
	Add(a, b Element) Element
	// Sub subtracts two extension field elements. The result is not reduced. The
	// degree of the result is the max of the degrees of the two operands.
	Sub(a, b Element) Element
	// MulByElement multiplies an extension field element by a native field
	// element. The result is not reduced. The degree of the result is the
	// degree of the extension field element.
	MulByElement(a Element, b frontend.Variable) Element
	// AssertIsEqual asserts that two extension field elements are strictly equal.
	// For equality in the extension field, reduce the elements first.
	AssertIsEqual(a, b Element)
	// Zero returns the zero element of the extension field. By convention it is
	// an empty polynomial.
	Zero() Element
	// One returns the one element of the extension field. By convention it is a
	// polynomial of degree 0.
	One() Element
	// AsExtensionVariable returns the native field element as an extension
	// field element of degree 0.
	AsExtensionVariable(a frontend.Variable) Element
	// Degree returns the degree of the extension field.
	Degree() int
}

// NewExtension returns a new extension field object.
func NewExtension(api frontend.API, opts ...Option) (Field, error) {
	cfg, err := newConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("apply options: %w", err)
	}
	// extension is provided
	if cfg.extension != nil {
		if cfg.extension[len(cfg.extension)-1] != 1 {
			return nil, fmt.Errorf("last coefficient of the extension must be 1")
		}
		et := simple
		if cfg.extension[0] == 1 {
			et = minimal
		}
		for i := 1; i < len(cfg.extension)-1; i++ {
			if cfg.extension[i] != 0 {
				et = generic
				break
			}
		}
		return &ext{api: api, extension: cfg.extension, extensionType: et}, nil
	}
	degree := "default"
	if cfg.degree != -1 {
		degree = strconv.Itoa(cfg.degree)
	}

	extension, ok := defaultExtensions[fmt.Sprintf("%s-%s", api.Compiler().Field(), degree)]
	if !ok {
		return nil, fmt.Errorf("no default extension for native modulus and not explicit extension provided")
	}
	return &ext{api: api, extension: extension, extensionType: simple}, nil
}

// Element is the extension field element.
type Element []frontend.Variable

func (e *ext) Reduce(a Element) Element {
	if e.extensionType == generic {
		// TODO: implement later
		panic("not implemented")
	}
	if len(a) < len(e.extension) {
		// no reduction needed
		return a
	}
	// we don't want to change a in place
	ret := make([]frontend.Variable, len(a))
	copy(ret, a)
	for len(ret) >= len(e.extension) {
		q := ret[len(e.extension)-1:]
		if e.extensionType == simple {
			// in case we have minimal extension, we don't need to multiply q by
			// the extension
			q = e.MulByElement(q, e.extension[0])
		}
		commonLen := min(len(q), len(e.extension)-1)
		for i := 0; i < commonLen; i++ {
			ret[i] = e.api.Add(ret[i], q[i])
		}
		for i := commonLen; i < len(q); i++ {
			ret[i] = q[i]
		}
		ret = ret[:max(len(q), len(e.extension)-1)]
	}
	return ret
}

func (e *ext) Mul(a, b Element) Element {
	ret := e.MulNoReduce(a, b)
	return e.Reduce(ret)
}

func (e *ext) MulNoReduce(a, b Element) Element {
	ret := make([]frontend.Variable, len(a)+len(b)-1)
	for i := range ret {
		ret[i] = 0
	}
	for i := range a {
		for j := range b {
			ret[i+j] = e.api.Add(ret[i+j], e.api.Mul(a[i], b[j]))
		}
	}
	return ret
}

func (e *ext) Add(a, b Element) Element {
	commonLen := min(len(a), len(b))
	ret := make([]frontend.Variable, max(len(a), len(b)))
	for i := 0; i < commonLen; i++ {
		ret[i] = e.api.Add(a[i], b[i])
	}
	for i := commonLen; i < len(a); i++ {
		ret[i] = a[i]
	}
	for i := commonLen; i < len(b); i++ {
		ret[i] = b[i]
	}
	return ret
}

func (e *ext) Sub(a, b Element) Element {
	commonLen := min(len(a), len(b))
	ret := make([]frontend.Variable, max(len(a), len(b)))
	for i := 0; i < commonLen; i++ {
		ret[i] = e.api.Sub(a[i], b[i])
	}
	for i := commonLen; i < len(a); i++ {
		ret[i] = a[i]
	}
	for i := commonLen; i < len(b); i++ {
		ret[i] = e.api.Neg(b[i])
	}
	return ret
}

func (e *ext) Div(a, b Element) Element {
	panic("not implemented")
}

func (e *ext) Inverse(a Element) Element {
	panic("not implemented")
}

func (e *ext) MulByElement(a Element, b frontend.Variable) Element {
	ret := make([]frontend.Variable, len(a))
	for i := range a {
		ret[i] = e.api.Mul(a[i], b)
	}
	return ret
}

func (e *ext) AssertIsEqual(a, b Element) {
	commonLen := min(len(a), len(b))
	for i := 0; i < commonLen; i++ {
		e.api.AssertIsEqual(a[i], b[i])
	}
	for i := commonLen; i < len(a); i++ {
		e.api.AssertIsEqual(a[i], 0)
	}
	for i := commonLen; i < len(b); i++ {
		e.api.AssertIsEqual(b[i], 0)
	}
}

func (e *ext) Zero() Element {
	return []frontend.Variable{}
}

func (e *ext) One() Element {
	return []frontend.Variable{1}
}

func (e *ext) AsExtensionVariable(a frontend.Variable) Element {
	return []frontend.Variable{a}
}

func (e *ext) Degree() int {
	return len(e.extension) - 1
}
