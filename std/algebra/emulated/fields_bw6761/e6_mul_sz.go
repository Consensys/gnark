package fields_bw6761

import (
	"math/big"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type e6mulCheck struct {
	A, B *E6
	R    *E6
	Q    *E6
}

func (mc *e6mulCheck) check(sapi *emulated.Field[emulated.BW6761Fp], rpowers []*baseEl, modEval *baseEl) {
	// a0 + a1*x + a2*x^2 + a3*x^3 + a4*x^4 + a5*x^5
	mv := emulated.ValueOfMultivariate[emulated.BW6761Fp](
		[][]int{
			{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			{0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0},
			{0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0},
			{0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0},
			{0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0},
			{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1},
		},
		[]*big.Int{
			big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1),
		},
	)
	mone := sapi.NewElement(-1)
	mv2 := emulated.ValueOfMultivariate[emulated.BW6761Fp](
		// r0 + r1 x + r2 x^2 + r3 x^3 + r4 x^4 + r5 x^5 + q0 np + q1 x np + q2 x^2 np + q3 x^3 np + q4 x^4 np - ax0 bx0 - ax1 bx1 - ax2 bx2 - ax3 bx3 - ax4 bx4 - ax5 bx5
		//   r0 r1 r2 r3 r4 r5 q0 q1 q2 q3 q4 x1 x2 x3 x4 x5 np ax bx -1
		[][]int{
			{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
			{0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
			{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},
			{0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0},

			{0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0},
			{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0},
			{0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0},
			{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0},
			{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0},

			{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1},
			// {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1},

			// {1, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			// {0, 1, 0, 0, 0, 1, 0, 0, 0, 1},
			// {0, 0, 1, 0, 0, 0, 1, 0, 0, 1},
			// {0, 0, 0, 1, 0, 0, 0, 1, 0, 1},
			// {0, 0, 0, 0, 1, 0, 0, 0, 1, 1},
		},
		[]*big.Int{
			big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1),
			big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1),
			big.NewInt(1),
		},
	)
	ax := sapi.EvalMultivariate(&mv, []*baseEl{&mc.A.A0, &mc.A.A1, &mc.A.A2, &mc.A.A3, &mc.A.A4, &mc.A.A5, rpowers[0], rpowers[1], rpowers[2], rpowers[3], rpowers[4]})
	var bx *emulated.Element[emulated.BW6761Fp]
	if mc.A != mc.B {
		bx = sapi.EvalMultivariate(&mv, []*baseEl{&mc.B.A0, &mc.B.A1, &mc.B.A2, &mc.B.A3, &mc.B.A4, &mc.B.A5, rpowers[0], rpowers[1], rpowers[2], rpowers[3], rpowers[4]})
	} else {
		bx = ax
	}
	// rx := sapi.EvalMultivariate(&mv, []*baseEl{&mc.R.A0, &mc.R.A1, &mc.R.A2, &mc.R.A3, &mc.R.A4, &mc.R.A5, rpowers[0], rpowers[1], rpowers[2], rpowers[3], rpowers[4]})
	// qnx := sapi.EvalMultivariate(&mv2, []*baseEl{&mc.Q.A0, &mc.Q.A1, &mc.Q.A2, &mc.Q.A3, &mc.Q.A4, rpowers[0], rpowers[1], rpowers[2], rpowers[3], modEval})
	// abx := sapi.Mul(ax, bx)
	rqnx := sapi.EvalMultivariate(&mv2, []*baseEl{
		&mc.R.A0, &mc.R.A1, &mc.R.A2, &mc.R.A3, &mc.R.A4, &mc.R.A5,
		&mc.Q.A0, &mc.Q.A1, &mc.Q.A2, &mc.Q.A3, &mc.Q.A4,
		rpowers[0], rpowers[1], rpowers[2], rpowers[3], rpowers[4],
		modEval,
		ax, bx, mone,
	})
	// rqnx := sapi.Add(rx, qnx)
	sapi.AssertIsEqual(rqnx, sapi.Zero())
	// sapi.AssertIsEqual(abx, rqnx)
}

func (e *Ext6) deferredMulChecks(api frontend.API) error {
	for k, v := range e.mulchecks {
		rpowers := make([]*baseEl, 6)
		rpowers[0] = k
		for i := 1; i < len(rpowers); i++ {
			rpowers[i] = e.fp.Mul(rpowers[i-1], k)
		}
		// x^6+4
		modeval := e.fp.Add(rpowers[5], e.fp.NewElement(4))

		for _, vv := range v {
			vv.check(e.fp, rpowers, modeval)
		}
	}
	return nil
}

func (e Ext6) squarePolyWithRand(x *E6, r *baseEl) *E6 {
	elems, err := e.fp.NewHint(mulE6Hint, 11, &x.A0, &x.A1, &x.A2, &x.A3, &x.A4, &x.A5, &x.A0, &x.A1, &x.A2, &x.A3, &x.A4, &x.A5)
	if err != nil {
		panic(err)
	}
	res := &E6{
		A0: *elems[0],
		A1: *elems[1],
		A2: *elems[2],
		A3: *elems[3],
		A4: *elems[4],
		A5: *elems[5],
	}
	quo := &E6{
		A0: *elems[6],
		A1: *elems[7],
		A2: *elems[8],
		A3: *elems[9],
		A4: *elems[10],
		A5: *e.fp.Zero(),
	}

	e.mulchecks[r] = append(e.mulchecks[r], e6mulCheck{
		A: x, B: x, R: res, Q: quo,
	})
	return res
}

func mulWithQuotient(in1, in2 []*big.Int) (remainder [6]*big.Int, quotient [5]*big.Int) {
	mod := bw6761.ID.BaseField()
	var A, B, R bw6761.E6
	A.B0.A0.SetBigInt(in1[0])
	A.B1.A0.SetBigInt(in1[1])
	A.B0.A1.SetBigInt(in1[2])
	A.B1.A1.SetBigInt(in1[3])
	A.B0.A2.SetBigInt(in1[4])
	A.B1.A2.SetBigInt(in1[5])

	B.B0.A0.SetBigInt(in2[0])
	B.B1.A0.SetBigInt(in2[1])
	B.B0.A1.SetBigInt(in2[2])
	B.B1.A1.SetBigInt(in2[3])
	B.B0.A2.SetBigInt(in2[4])
	B.B1.A2.SetBigInt(in2[5])

	R.Mul(&A, &B)

	remainder = [6]*big.Int{
		R.B0.A0.BigInt(new(big.Int)),
		R.B1.A0.BigInt(new(big.Int)),
		R.B0.A1.BigInt(new(big.Int)),
		R.B1.A1.BigInt(new(big.Int)),
		R.B0.A2.BigInt(new(big.Int)),
		R.B1.A2.BigInt(new(big.Int)),
	}

	lhs := make([]*big.Int, 11)
	for i := range lhs {
		lhs[i] = new(big.Int)
	}
	for i := range in1 {
		for j := range in2 {
			lhs[i+j].Add(lhs[i+j], new(big.Int).Mul(in1[i], in2[j]))
		}
	}
	for i := range remainder {
		lhs[i].Sub(lhs[i], remainder[i])
	}

	for i := range lhs {
		lhs[i].Mod(lhs[i], mod)
		// fmt.Println(i, lhs[i].String())
	}

	for i := 0; i < 5; i++ {
		quotient[i] = new(big.Int).Set(lhs[i+6])
	}

	for i := range quotient {
		quotient[i].Mod(quotient[i], mod)
		// fmt.Println(i, quotient[i].String())
	}
	return
}

func mulE6Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			remainder, quotient := mulWithQuotient(inputs[0:6], inputs[6:12])
			for i := range remainder {
				outputs[i].Set(remainder[i])
			}
			for i := range quotient {
				outputs[i+6].Set(quotient[i])
			}
			return nil
		})
}
