package internal

import (
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
	"math/big"
)

// wrap BN254 scalar field arithmetic in a frontend.API
// bn254WrapperApi uses *fr.Element as its variable type
type bn254WrapperApi struct {
	err error
}

func ToBn254GateFunction(f func(frontend.API, ...frontend.Variable) frontend.Variable) gkr.GateFunction {
	var wrapper bn254WrapperApi

	return func(x ...fr.Element) fr.Element {
		res := f(&wrapper, utils.Map(x, func(x fr.Element) frontend.Variable {
			return &x
		})...).(*fr.Element)
		if wrapper.err != nil {
			panic(wrapper.err)
		}
		return *res
	}
}

func (w *bn254WrapperApi) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	var res fr.Element
	res.Add(w.cast(i1), w.cast(i2))
	for i := range in {
		res.Add(&res, w.cast(in[i]))
	}

	return &res
}

func (w *bn254WrapperApi) MulAcc(a, b, c frontend.Variable) frontend.Variable {
	var res fr.Element
	res.Mul(w.cast(b), w.cast(c))
	res.Add(&res, w.cast(a))
	return &res
}

func (w *bn254WrapperApi) Neg(i1 frontend.Variable) frontend.Variable {
	var res fr.Element
	res.Neg(w.cast(i1))
	return &res
}

func (w *bn254WrapperApi) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	var res fr.Element
	res.Sub(w.cast(i1), w.cast(i2))
	for i := range in {
		res.Sub(&res, w.cast(in[i]))
	}
	return &res
}

func (w *bn254WrapperApi) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	var res fr.Element
	res.Mul(w.cast(i1), w.cast(i2))
	for i := range in {
		res.Mul(&res, w.cast(in[i]))
	}
	return &res
}

func (w *bn254WrapperApi) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	return w.Div(i1, i2)
}

func (w *bn254WrapperApi) Div(i1, i2 frontend.Variable) frontend.Variable {
	return w.Mul(i1, w.Inverse(i2))
}

func (w *bn254WrapperApi) Inverse(i1 frontend.Variable) frontend.Variable {
	w.newError("only polynomial (ring) operations supported")
	return nil
}

func (w *bn254WrapperApi) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	w.newError("only field operations supported")
	return nil
}

func (w *bn254WrapperApi) FromBinary(b ...frontend.Variable) frontend.Variable {
	w.newError("only field operations supported")
	return nil
}

func (w *bn254WrapperApi) Xor(a, b frontend.Variable) frontend.Variable {
	w.newError("only field operations supported")
	return nil
}

func (w *bn254WrapperApi) Or(a, b frontend.Variable) frontend.Variable {
	w.newError("only field operations supported")
	return nil
}

func (w *bn254WrapperApi) And(a, b frontend.Variable) frontend.Variable {
	w.newError("only field operations supported")
	return nil
}

func (w *bn254WrapperApi) Select(frontend.Variable, frontend.Variable, frontend.Variable) frontend.Variable {
	w.newError("only field operations supported")
	return nil
}

func (w *bn254WrapperApi) Lookup2(frontend.Variable, frontend.Variable, frontend.Variable, frontend.Variable, frontend.Variable, frontend.Variable) frontend.Variable {
	w.newError("only field operations supported")
	return nil
}

func (w *bn254WrapperApi) IsZero(frontend.Variable) frontend.Variable {
	w.newError("only field operations supported")
	return nil
}

func (w *bn254WrapperApi) Cmp(frontend.Variable, frontend.Variable) frontend.Variable {
	w.newError("only field operations supported")
	return nil
}

func (w *bn254WrapperApi) AssertIsEqual(i1, i2 frontend.Variable) {
	w.newError("only field operations supported")
}

func (w *bn254WrapperApi) AssertIsDifferent(frontend.Variable, frontend.Variable) {
	w.newError("only field operations supported")
}

func (w *bn254WrapperApi) AssertIsBoolean(frontend.Variable) {
	w.newError("only field operations supported")
}

func (w *bn254WrapperApi) AssertIsCrumb(frontend.Variable) {
	w.newError("only field operations supported")
}

func (w *bn254WrapperApi) AssertIsLessOrEqual(frontend.Variable, frontend.Variable) {
	w.newError("only field operations supported")
}

func (w *bn254WrapperApi) Println(a ...frontend.Variable) {
	toPrint := make([]any, len(a))
	for i, v := range a {
		var x fr.Element
		if _, err := x.SetInterface(v); err != nil {
			if s, ok := v.(string); ok {
				toPrint[i] = s
				continue
			} else {
				w.newError("not numeric or string")
			}
		} else {
			toPrint[i] = x.String()
		}
	}
	fmt.Println(toPrint...)
}

func (w *bn254WrapperApi) Compiler() frontend.Compiler {
	w.newError("only field operations supported")
	return nil
}

func (w *bn254WrapperApi) NewHint(solver.Hint, int, ...frontend.Variable) ([]frontend.Variable, error) {
	err := errors.New("only field operations supported")
	w.emitError(err)
	return nil, err
}

func (w *bn254WrapperApi) ConstantValue(frontend.Variable) (*big.Int, bool) {
	w.newError("only field operations supported")
	return nil, false
}

func (w *bn254WrapperApi) cast(v frontend.Variable) *fr.Element {
	var res fr.Element
	if w.err != nil {
		return &res
	}
	if _, err := res.SetInterface(v); err != nil {
		w.emitError(err)
	}
	return &res
}

func (w *bn254WrapperApi) emitError(err error) {
	if w.err == nil {
		w.err = err
	}
}

func (w *bn254WrapperApi) newError(msg string) {
	w.emitError(errors.New(msg))
}
