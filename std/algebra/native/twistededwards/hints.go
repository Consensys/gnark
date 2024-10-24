package twistededwards

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

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
		halfGCD,
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

func halfGCD(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return fmt.Errorf("expecting two inputs")
	}
	if len(outputs) != 4 {
		return fmt.Errorf("expecting four outputs")
	}
	glvBasis := new(ecc.Lattice)
	ecc.PrecomputeLattice(inputs[1], inputs[0], glvBasis)
	outputs[0].Set(&glvBasis.V1[0])
	outputs[1].Set(&glvBasis.V1[1])

	// figure out how many times we have overflowed
	// s2 * s + s1 = k*r
	outputs[3].Mul(outputs[1], inputs[0]).
		Add(outputs[3], outputs[0]).
		Div(outputs[3], inputs[1])

	outputs[2].SetUint64(0)
	if outputs[1].Sign() == -1 {
		outputs[1].Neg(outputs[1])
		outputs[2].SetUint64(1)
	}

	return nil
}

func scalarMulHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 4 {
		return fmt.Errorf("expecting four inputs")
	}
	if len(outputs) != 2 {
		return fmt.Errorf("expecting two outputs")
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
		return fmt.Errorf("scalarMulHint: unknown curve")
	}
	return nil
}
