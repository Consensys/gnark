package twistededwards

import (
	"errors"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	"github.com/consensys/gnark-crypto/ecc"
	edbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/bandersnatch"
	jubjub "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	edbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards"
	edbls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/twistededwards"
	babyjubjub "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	edbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/twistededwards"
	edbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	"github.com/consensys/gnark/constraint/solver"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		rationalReconstruct,
		scalarMulHint,
		decomposeScalar,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

type glvParams struct {
	lambda, order big.Int
	glvBasis      ecc.Lattice
}

func decomposeScalar(scalarField *big.Int, inputs []*big.Int, res []*big.Int) error {
	// the efficient endomorphism exists on Bandersnatch only
	if scalarField.Cmp(ecc.BLS12_381.ScalarField()) != 0 {
		return errors.New("no efficient endomorphism is available on this curve")
	}
	var glv glvParams
	var init sync.Once
	init.Do(func() {
		glv.lambda.SetString("8913659658109529928382530854484400854125314752504019737736543920008458395397", 10)
		glv.order.SetString("13108968793781547619861935127046491459309155893440570251786403306729687672801", 10)
		ecc.PrecomputeLattice(&glv.order, &glv.lambda, &glv.glvBasis)
	})

	// sp[0] is always negative because, in SplitScalar(), we always round above
	// the determinant/2 computed in PrecomputeLattice() which is negative for Bandersnatch.
	// Thus taking -sp[0] here and negating the point in ScalarMul().
	// If we keep -sp[0] it will be reduced mod r (the BLS12-381 prime order)
	// and not the Bandersnatch prime order (Order) and the result will be incorrect.
	// Also, if we reduce it mod Order here, we can't use api.ToBinary(sp[0], 129)
	// and hence we can't reduce optimally the number of constraints.
	sp := ecc.SplitScalar(inputs[0], &glv.glvBasis)
	res[0].Neg(&(sp[0]))
	res[1].Set(&(sp[1]))

	// figure out how many times we have overflowed
	res[2].Mul(res[1], &glv.lambda).Sub(res[2], res[0])
	res[2].Sub(res[2], inputs[0])
	res[2].Div(res[2], &glv.order)

	return nil
}

func rationalReconstruct(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two inputs")
	}
	if len(outputs) != 4 {
		return errors.New("expecting four outputs")
	}
	// Handle zero scalar case
	if inputs[0].Sign() == 0 {
		outputs[0].SetUint64(0)
		outputs[1].SetUint64(0)
		outputs[2].SetUint64(0)
		outputs[3].SetUint64(0)
		return nil
	}

	// Use lattice reduction to find (x, z) such that s ≡ x/z (mod r),
	// i.e., x - s*z ≡ 0 (mod r), or equivalently x + s*(-z) ≡ 0 (mod r).
	// The circuit checks: s1 + s*_s2 ≡ 0 (mod r)
	// So we need s1 = x and _s2 = -z.
	res := lattice.RationalReconstruct(inputs[0], inputs[1])
	x, z := res[0], res[1]

	// Ensure x is non-negative (the circuit bit-decomposes s1 assuming it's small positive).
	// If x < 0, flip signs: (x, z) -> (-x, -z), which preserves s = x/z.
	if x.Sign() < 0 {
		x.Neg(x)
		z.Neg(z)
	}

	outputs[0].Set(x)
	outputs[1].Abs(z)

	// The sign indicates whether to negate s2 in circuit to get -z.
	// sign = 1 when z > 0 (so -z < 0, and we need to negate |z| to get -z)
	outputs[2].SetUint64(0)
	if z.Sign() > 0 {
		outputs[2].SetUint64(1)
	}

	// Compute overflow: k = (x - s*z) / r
	// The constraint is x - s*z ≡ 0 (mod r), so x - s*z = k*r for some integer k
	// We need to keep the sign of k for the circuit to work correctly.
	outputs[3].Mul(z, inputs[0])          // s*z
	outputs[3].Sub(x, outputs[3])         // x - s*z
	outputs[3].Div(outputs[3], inputs[1]) // k = (x - s*z) / r

	return nil
}

func scalarMulHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 4 {
		return errors.New("expecting four inputs")
	}
	if len(outputs) != 2 {
		return errors.New("expecting two outputs")
	}
	// compute the resulting point [s]Q
	if field.Cmp(ecc.BLS12_381.ScalarField()) == 0 {
		order, _ := new(big.Int).SetString("13108968793781547619861935127046491459309155893440570251786403306729687672801", 10)
		if inputs[3].Cmp(order) == 0 {
			var P bandersnatch.PointAffine
			P.X.SetBigInt(inputs[0])
			P.Y.SetBigInt(inputs[1])
			P.ScalarMultiplication(&P, inputs[2])
			P.X.BigInt(outputs[0])
			P.Y.BigInt(outputs[1])
		} else {
			var P jubjub.PointAffine
			P.X.SetBigInt(inputs[0])
			P.Y.SetBigInt(inputs[1])
			P.ScalarMultiplication(&P, inputs[2])
			P.X.BigInt(outputs[0])
			P.Y.BigInt(outputs[1])
		}
	} else if field.Cmp(ecc.BN254.ScalarField()) == 0 {
		var P babyjubjub.PointAffine
		P.X.SetBigInt(inputs[0])
		P.Y.SetBigInt(inputs[1])
		P.ScalarMultiplication(&P, inputs[2])
		P.X.BigInt(outputs[0])
		P.Y.BigInt(outputs[1])
	} else if field.Cmp(ecc.BLS12_377.ScalarField()) == 0 {
		var P edbls12377.PointAffine
		P.X.SetBigInt(inputs[0])
		P.Y.SetBigInt(inputs[1])
		P.ScalarMultiplication(&P, inputs[2])
		P.X.BigInt(outputs[0])
		P.Y.BigInt(outputs[1])
	} else if field.Cmp(ecc.BLS24_315.ScalarField()) == 0 {
		var P edbls24315.PointAffine
		P.X.SetBigInt(inputs[0])
		P.Y.SetBigInt(inputs[1])
		P.ScalarMultiplication(&P, inputs[2])
		P.X.BigInt(outputs[0])
		P.Y.BigInt(outputs[1])
	} else if field.Cmp(ecc.BLS24_317.ScalarField()) == 0 {
		var P edbls24317.PointAffine
		P.X.SetBigInt(inputs[0])
		P.Y.SetBigInt(inputs[1])
		P.ScalarMultiplication(&P, inputs[2])
		P.X.BigInt(outputs[0])
		P.Y.BigInt(outputs[1])
	} else if field.Cmp(ecc.BW6_761.ScalarField()) == 0 {
		var P edbw6761.PointAffine
		P.X.SetBigInt(inputs[0])
		P.Y.SetBigInt(inputs[1])
		P.ScalarMultiplication(&P, inputs[2])
		P.X.BigInt(outputs[0])
		P.Y.BigInt(outputs[1])
	} else if field.Cmp(ecc.BW6_633.ScalarField()) == 0 {
		var P edbw6633.PointAffine
		P.X.SetBigInt(inputs[0])
		P.Y.SetBigInt(inputs[1])
		P.ScalarMultiplication(&P, inputs[2])
		P.X.BigInt(outputs[0])
		P.Y.BigInt(outputs[1])
	} else {
		return errors.New("scalarMulHint: unknown curve")
	}
	return nil
}
