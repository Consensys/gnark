package gkr

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	frBls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	gkrBls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/gkr"
	frBls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gkrBls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/gkr"
	frBls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	gkrBls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/gkr"
	frBls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	gkrBls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr/gkr"
	frBn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	gkrBn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	frBw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	gkrBw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr/gkr"
	frBw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	gkrBw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/gkr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
	"math/big"
)

func (f GateFunction) toFrGateFunction(curve ecc.ID) frGateFunction {
	w := &wrapperApi{curve.ScalarField()}

	switch curve {
	case ecc.BLS12_377:
		return gkrBls12377.GateFunction(func(x ...frBls12377.Element) frBls12377.Element {
			var res frBls12377.Element
			_, err := res.SetInterface(f(w, toVars(x)...))
			assertNoError(err)
			return res
		})

	case ecc.BLS12_381:
		return gkrBls12381.GateFunction(func(x ...frBls12381.Element) frBls12381.Element {
			var res frBls12381.Element
			_, err := res.SetInterface(f(w, toVars(x)...))
			assertNoError(err)
			return res
		})

	case ecc.BLS24_315:
		return gkrBls24315.GateFunction(func(x ...frBls24315.Element) frBls24315.Element {
			var res frBls24315.Element
			_, err := res.SetInterface(f(w, toVars(x)...))
			assertNoError(err)
			return res
		})

	case ecc.BLS24_317:
		return gkrBls24317.GateFunction(func(x ...frBls24317.Element) frBls24317.Element {
			var res frBls24317.Element
			_, err := res.SetInterface(f(w, toVars(x)...))
			assertNoError(err)
			return res
		})

	case ecc.BN254:
		return gkrBn254.GateFunction(func(x ...frBn254.Element) frBn254.Element {
			var res frBn254.Element
			_, err := res.SetInterface(f(w, toVars(x)...))
			assertNoError(err)
			return res
		})

	case ecc.BW6_633:
		return gkrBw6633.GateFunction(func(x ...frBw6633.Element) frBw6633.Element {
			var res frBw6633.Element
			_, err := res.SetInterface(f(w, toVars(x)...))
			assertNoError(err)
			return res
		})

	case ecc.BW6_761:
		return gkrBw6761.GateFunction(func(x ...frBw6761.Element) frBw6761.Element {
			var res frBw6761.Element
			_, err := res.SetInterface(f(w, toVars(x)...))
			assertNoError(err)
			return res
		})
	}

	panic(fmt.Errorf("unsupported curve %s", curve.String()))
}

func toVars[T any](v []T) []frontend.Variable {
	res := make([]frontend.Variable, len(v))
	for i := range v {
		res[i] = v[i]
	}
	return res
}

func (w *wrapperApi) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	a := utils.ForceFromInterface(i1)
	b := utils.ForceFromInterface(i2)
	a.Add(&a, &b)
	for i := range in {
		b = utils.ForceFromInterface(in[i])
		a.Add(&a, &b)
	}
	a.Mod(&a, w.mod)

	return a
}

func (w *wrapperApi) MulAcc(a, b, c frontend.Variable) frontend.Variable {
	x := utils.ForceFromInterface(b)
	y := utils.ForceFromInterface(c)
	x.Mul(&x, &y)
	y = utils.ForceFromInterface(a)
	x.Add(&x, &y)
	x.Mod(&x, w.mod)
	return x
}

func (w *wrapperApi) Neg(i1 frontend.Variable) frontend.Variable {
	x := utils.ForceFromInterface(i1)
	x.Sub(w.mod, &x)

	return x
}

func (w *wrapperApi) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	x := utils.ForceFromInterface(i1)
	y := utils.ForceFromInterface(i2)
	x.Sub(&x, &y)

	for i := range in {
		y = utils.ForceFromInterface(in[i])
		x.Sub(&x, &y)
	}
	x.Mod(&x, w.mod)

	return x
}

func (w *wrapperApi) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	x := utils.ForceFromInterface(i1)
	y := utils.ForceFromInterface(i2)
	x.Mul(&x, &y)
	x.Mod(&x, w.mod)

	for i := range in {
		y = utils.ForceFromInterface(in[i])
		x.Mul(&x, &y)
		x.Mod(&x, w.mod)
	}
	return x
}

func (w *wrapperApi) Println(a ...frontend.Variable) {
	toPrint := make([]any, len(a))
	for i, v := range a {
		x, err := utils.FromInterface(v)
		if err != nil {
			if s, ok := v.(string); ok {
				toPrint[i] = s
				continue
			}
			panic(fmt.Errorf("not numeric or string: %w", err))
		} else {
			toPrint[i] = x.String()
		}
	}
	fmt.Println(toPrint...)
}

type wrapperApi struct {
	mod *big.Int
}

type frGateFunction interface {
	FindDegree(maxAutoDegreeBound int, nbIn int) (int, error)
	VerifyDegree(degree int, nbIn int) error
	IsVarSolvable(varIndex int, nbIn int) bool
	FindSolvableVar(nbIn int) int
}

func assertNoError(err error) {
	if err != nil {
		panic(err)
	}
}
