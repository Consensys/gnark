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

type Extension struct {
	api frontend.API

	extension []int // we expect the extension defining modulus to have small small coefficients
	extensionType
}

// NewExtension returns a new extension field object.
func NewExtension(api frontend.API, opts ...Option) (*Extension, error) {
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
		return &Extension{api: api, extension: cfg.extension, extensionType: et}, nil
	}
	degree := "default"
	if cfg.degree != -1 {
		degree = strconv.Itoa(cfg.degree)
	}

	extension, ok := defaultExtensions[fmt.Sprintf("%s-%s", api.Compiler().Field(), degree)]
	if !ok {
		return nil, fmt.Errorf("no default extension for native modulus and not explicit extension provided")
	}
	return &Extension{api: api, extension: extension, extensionType: simple}, nil
}

type ExtensionVariable []frontend.Variable

func (e *Extension) Reduce(a ExtensionVariable) []frontend.Variable {
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

func (e *Extension) Mul(a, b ExtensionVariable) ExtensionVariable {
	ret := e.MulNoReduce(a, b)
	return e.Reduce(ret)
}

func (e *Extension) MulNoReduce(a, b ExtensionVariable) ExtensionVariable {
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

func (e *Extension) Add(a, b ExtensionVariable) ExtensionVariable {
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

func (e *Extension) Sub(a, b ExtensionVariable) ExtensionVariable {
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

func (e *Extension) Div(a, b ExtensionVariable) ExtensionVariable {
	panic("not implemented")
}

func (e *Extension) Inverse(a ExtensionVariable) ExtensionVariable {
	panic("not implemented")
}

func (e *Extension) MulByElement(a ExtensionVariable, b frontend.Variable) ExtensionVariable {
	ret := make([]frontend.Variable, len(a))
	for i := range a {
		ret[i] = e.api.Mul(a[i], b)
	}
	return ret
}

func (e *Extension) AssertIsEqual(a, b ExtensionVariable) {
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

func (e *Extension) Zero() ExtensionVariable {
	ret := make(ExtensionVariable, len(e.extension))
	for i := range ret {
		ret[i] = frontend.Variable(0)
	}
	return ret
}

func (e *Extension) One() ExtensionVariable {
	ret := make(ExtensionVariable, len(e.extension))
	ret[0] = frontend.Variable(1)
	for i := 1; i < len(ret); i++ {
		ret[i] = frontend.Variable(0)
	}
	return ret
}

func (e *Extension) AsExtensionVariable(a frontend.Variable) ExtensionVariable {
	ret := make(ExtensionVariable, len(e.extension))
	ret[0] = a
	for i := 1; i < len(ret); i++ {
		ret[i] = frontend.Variable(0)
	}
	return ret
}

func (e *Extension) Degree() int {
	return len(e.extension) - 1
}
