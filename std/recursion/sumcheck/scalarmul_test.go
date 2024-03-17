package sumcheck

import (
	"crypto/rand"
	"fmt"
	"math/big"
	stdbits "math/bits"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fr_secp256k1 "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	cryptofs "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/math/polynomial"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/test"
)

type ProjectivePoint[Base emulated.FieldParams] struct {
	X, Y, Z emulated.Element[Base]
}

type ScalarMulCircuit[Base, Scalars emulated.FieldParams] struct {
	Points  []sw_emulated.AffinePoint[Base]
	Scalars []emulated.Element[Scalars]

	nbScalarBits int
}

func (c *ScalarMulCircuit[B, S]) Define(api frontend.API) error {
	var fp B
	nbInputs := len(c.Points)
	if len(c.Points) != len(c.Scalars) {
		return fmt.Errorf("len(inputs) != len(scalars)")
	}
	baseApi, err := emulated.NewField[B](api)
	if err != nil {
		return fmt.Errorf("new base field: %w", err)
	}
	scalarApi, err := emulated.NewField[S](api)
	if err != nil {
		return fmt.Errorf("new scalar field: %w", err)
	}
	poly, err := polynomial.New[B](api)
	if err != nil {
		return fmt.Errorf("new polynomial: %w", err)
	}
	// we use curve for marshaling points and scalars
	curve, err := algebra.GetCurve[S, sw_emulated.AffinePoint[B]](api)
	if err != nil {
		return fmt.Errorf("get curve: %w", err)
	}
	fs, err := recursion.NewTranscript(api, fp.Modulus(), []string{"alpha", "beta"})
	if err != nil {
		return fmt.Errorf("new transcript: %w", err)
	}
	// compute the all double-and-add steps for each scalar multiplication
	// var results, accs []ProjectivePoint[B]
	for i := range c.Points {
		if err := fs.Bind("alpha", curve.MarshalG1(c.Points[i])); err != nil {
			return fmt.Errorf("bind point %d alpha: %w", i, err)
		}
		if err := fs.Bind("alpha", curve.MarshalScalar(c.Scalars[i])); err != nil {
			return fmt.Errorf("bind scalar %d alpha: %w", i, err)
		}
	}
	result, acc, proof, err := callHintScalarMulSteps[B, S](api, baseApi, scalarApi, c.nbScalarBits, c.Points, c.Scalars)
	if err != nil {
		return fmt.Errorf("hint scalar mul steps: %w", err)
	}

	// derive the randomness for random linear combination
	alphaNative, err := fs.ComputeChallenge("alpha")
	if err != nil {
		return fmt.Errorf("compute challenge alpha: %w", err)
	}
	alphaBts := bits.ToBinary(api, alphaNative, bits.WithNbDigits(fp.Modulus().BitLen()))
	alphas := make([]*emulated.Element[B], 6)
	alphas[0] = baseApi.One()
	alphas[1] = baseApi.FromBits(alphaBts...)
	for i := 2; i < len(alphas); i++ {
		alphas[i] = baseApi.Mul(alphas[i-1], alphas[1])
	}
	claimed := make([]*emulated.Element[B], nbInputs*c.nbScalarBits)
	// compute the random linear combinations of the intermediate results provided by the hint
	for i := 0; i < nbInputs; i++ {
		for j := 0; j < c.nbScalarBits; j++ {
			claimed[i*c.nbScalarBits+j] = baseApi.Sum(
				&acc[i][j].X,
				baseApi.MulNoReduce(alphas[1], &acc[i][j].Y),
				baseApi.MulNoReduce(alphas[2], &acc[i][j].Z),
				baseApi.MulNoReduce(alphas[3], &result[i][j].X),
				baseApi.MulNoReduce(alphas[4], &result[i][j].Y),
				baseApi.MulNoReduce(alphas[5], &result[i][j].Z),
			)
		}
	}
	// derive the randomness for folding
	betaNative, err := fs.ComputeChallenge("beta")
	if err != nil {
		return fmt.Errorf("compute challenge alpha: %w", err)
	}
	betaBts := bits.ToBinary(api, betaNative, bits.WithNbDigits(fp.Modulus().BitLen()))
	evalPoints := make([]*emulated.Element[B], stdbits.Len(uint(len(claimed)))-1)
	evalPoints[0] = baseApi.FromBits(betaBts...)
	for i := 1; i < len(evalPoints); i++ {
		evalPoints[i] = baseApi.Mul(evalPoints[i-1], evalPoints[0])
	}
	// compute the polynomial evaluation
	claimedPoly := polynomial.FromSliceReferences(claimed)
	evaluation, err := poly.EvalMultilinear(evalPoints, claimedPoly)
	if err != nil {
		return fmt.Errorf("eval multilinear: %w", err)
	}
	fmt.Printf("claim: %s\n", baseApi.String(evaluation))

	inputs := make([][]*emulated.Element[B], 7)
	for i := range inputs {
		inputs[i] = make([]*emulated.Element[B], nbInputs*c.nbScalarBits)
	}
	for i := 0; i < nbInputs; i++ {
		scalarBts := scalarApi.ToBits(&c.Scalars[i])
		for j := 0; j < c.nbScalarBits; j++ {
			inputs[0][i*c.nbScalarBits+j] = &acc[i][j].X
			inputs[1][i*c.nbScalarBits+j] = &acc[i][j].Y
			inputs[2][i*c.nbScalarBits+j] = &acc[i][j].Z
			inputs[3][i*c.nbScalarBits+j] = &result[i][j].X
			inputs[4][i*c.nbScalarBits+j] = &result[i][j].Y
			inputs[5][i*c.nbScalarBits+j] = &result[i][j].Z
			inputs[6][i*c.nbScalarBits+j] = baseApi.NewElement(scalarBts[j])
		}
	}
	gate := dblAddSelectGate[*emuEngine[B], *emulated.Element[B]]{folding: alphas}
	claim, err := newGate[B](api, gate, inputs, [][]*emulated.Element[B]{evalPoints}, []*emulated.Element[B]{evaluation})
	v, err := NewVerifier[B](api)
	if err != nil {
		return fmt.Errorf("new sumcheck verifier: %w", err)
	}
	if err = v.Verify(claim, proof); err != nil {
		return fmt.Errorf("verify sumcheck: %w", err)
	}
	_ = evaluation

	return nil
}

func callHintScalarMulSteps[B, S emulated.FieldParams](api frontend.API,
	baseApi *emulated.Field[B], scalarApi *emulated.Field[S],
	nbScalarBits int,
	points []sw_emulated.AffinePoint[B], scalars []emulated.Element[S]) (results [][]ProjectivePoint[B], accumulators [][]ProjectivePoint[B], proof Proof[B], err error) {
	var fp B
	var fr S
	nbInputs := len(points)
	inputs := []frontend.Variable{nbInputs, fp.BitsPerLimb(), fp.NbLimbs(), fr.BitsPerLimb(), fr.NbLimbs()}
	inputs = append(inputs, baseApi.Modulus().Limbs...)
	inputs = append(inputs, scalarApi.Modulus().Limbs...)
	for i := range points {
		inputs = append(inputs, points[i].X.Limbs...)
		inputs = append(inputs, points[i].Y.Limbs...)
		inputs = append(inputs, scalars[i].Limbs...)
	}
	// steps part
	nbRes := nbScalarBits * int(fp.NbLimbs()) * 6 * nbInputs
	// proof part
	nbRes += int(fp.NbLimbs()) * (stdbits.Len(uint(nbInputs*nbScalarBits)) - 1) * (dblAddSelectGate[*noopEngine, element]{}.Degree() + 1)
	hintRes, err := api.Compiler().NewHint(hintScalarMulSteps, nbRes, inputs...)
	if err != nil {
		return nil, nil, proof, fmt.Errorf("new hint: %w", err)
	}
	res := make([][]ProjectivePoint[B], nbInputs)
	acc := make([][]ProjectivePoint[B], nbInputs)
	for i := 0; i < nbInputs; i++ {
		res[i] = make([]ProjectivePoint[B], nbScalarBits)
		acc[i] = make([]ProjectivePoint[B], nbScalarBits)
	}
	for i := 0; i < nbInputs; i++ {
		inputRes := hintRes[i*(6*int(fp.NbLimbs())*nbScalarBits) : (i+1)*(6*int(fp.NbLimbs())*nbScalarBits)]
		for j := 0; j < nbScalarBits; j++ {
			coords := make([]*emulated.Element[B], 6)
			for k := range coords {
				limbs := inputRes[j*(6*int(fp.NbLimbs()))+k*int(fp.NbLimbs()) : j*(6*int(fp.NbLimbs()))+(k+1)*int(fp.NbLimbs())]
				coords[k] = baseApi.NewElement(limbs)
			}
			res[i][j] = ProjectivePoint[B]{
				X: *coords[0],
				Y: *coords[1],
				Z: *coords[2],
			}
			acc[i][j] = ProjectivePoint[B]{
				X: *coords[3],
				Y: *coords[4],
				Z: *coords[5],
			}
		}
	}
	proof.RoundPolyEvaluations = make([]polynomial.Univariate[B], stdbits.Len(uint(nbInputs*nbScalarBits))-1)
	ptr := nbInputs * 6 * int(fp.NbLimbs()) * nbScalarBits
	for i := range proof.RoundPolyEvaluations {
		proof.RoundPolyEvaluations[i] = make(polynomial.Univariate[B], dblAddSelectGate[*noopEngine, element]{}.Degree()+1)
		for j := range proof.RoundPolyEvaluations[i] {
			limbs := hintRes[ptr : ptr+int(fp.NbLimbs())]
			el := baseApi.NewElement(limbs)
			proof.RoundPolyEvaluations[i][j] = *el
			ptr += int(fp.NbLimbs())
		}
	}
	return res, acc, proof, nil
}

func hintScalarMulSteps(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	nbInputs := int(inputs[0].Int64())
	nbBits := int(inputs[1].Int64())
	nbLimbs := int(inputs[2].Int64())
	nbScalarBits := int(inputs[3].Int64())
	nbScalarLimbs := int(inputs[4].Int64())
	fpLimbs := inputs[5 : 5+nbLimbs]
	frLimbs := inputs[5+nbLimbs : 5+nbLimbs+nbScalarLimbs]
	fp := new(big.Int)
	fr := new(big.Int)
	if err := recompose(fpLimbs, uint(nbBits), fp); err != nil {
		return fmt.Errorf("recompose fp: %w", err)
	}
	if err := recompose(frLimbs, uint(nbScalarBits), fr); err != nil {
		return fmt.Errorf("recompose fr: %w", err)
	}
	ptr := 5 + nbLimbs + nbScalarLimbs
	xs := make([]*big.Int, nbInputs)
	ys := make([]*big.Int, nbInputs)
	scalars := make([]*big.Int, nbInputs)
	for i := 0; i < nbInputs; i++ {
		xLimbs := inputs[ptr : ptr+nbLimbs]
		ptr += nbLimbs
		yLimbs := inputs[ptr : ptr+nbLimbs]
		ptr += nbLimbs
		scalarLimbs := inputs[ptr : ptr+nbScalarLimbs]
		ptr += nbScalarLimbs
		xs[i] = new(big.Int)
		ys[i] = new(big.Int)
		scalars[i] = new(big.Int)
		if err := recompose(xLimbs, uint(nbBits), xs[i]); err != nil {
			return fmt.Errorf("recompose x: %w", err)
		}
		if err := recompose(yLimbs, uint(nbBits), ys[i]); err != nil {
			return fmt.Errorf("recompose y: %w", err)
		}
		if err := recompose(scalarLimbs, uint(nbScalarBits), scalars[i]); err != nil {
			return fmt.Errorf("recompose scalar: %w", err)
		}
	}

	// first, we need to provide the steps of the scalar multiplication to the
	// verifier. As the output of one step is an input of the next step, we need
	// to provide the results and the accumulators. By checking the consistency
	// of the inputs related to the outputs (inputs using multilinear evaluation
	// in the final round of the sumcheck and outputs by requiring the verifier
	// to construct the claim itself), we can ensure that the final step is the
	// actual scalar multiplication result.
	scalarLength := len(outputs) / (6 * nbLimbs * nbInputs)
	api := newBigIntEngine(fp)
	selector := new(big.Int)
	outPtr := 0
	proofInput := make([][]*big.Int, 7)
	for i := range proofInput {
		proofInput[i] = make([]*big.Int, nbInputs*scalarLength)
	}
	for i := 0; i < nbInputs; i++ {
		scalar := new(big.Int).Set(scalars[i])
		x := xs[i]
		y := ys[i]
		accX := new(big.Int).Set(x)
		accY := new(big.Int).Set(y)
		accZ := big.NewInt(1)
		resultX := big.NewInt(0)
		resultY := big.NewInt(1)
		resultZ := big.NewInt(0)
		for j := 0; j < scalarLength; j++ {
			selector.And(scalar, big.NewInt(1))
			scalar.Rsh(scalar, 1)
			proofInput[0][i*scalarLength+j] = new(big.Int).Set(accX)
			proofInput[1][i*scalarLength+j] = new(big.Int).Set(accY)
			proofInput[2][i*scalarLength+j] = new(big.Int).Set(accZ)
			proofInput[3][i*scalarLength+j] = new(big.Int).Set(resultX)
			proofInput[4][i*scalarLength+j] = new(big.Int).Set(resultY)
			proofInput[5][i*scalarLength+j] = new(big.Int).Set(resultZ)
			proofInput[6][i*scalarLength+j] = new(big.Int).Set(selector)
			tmpX, tmpY, tmpZ := projAdd(api, accX, accY, accZ, resultX, resultY, resultZ)
			resultX, resultY, resultZ = projSelect(api, selector, tmpX, tmpY, tmpZ, resultX, resultY, resultZ)
			accX, accY, accZ = projDbl(api, accX, accY, accZ)
			if err := decompose(resultX, uint(nbBits), outputs[outPtr:outPtr+nbLimbs]); err != nil {
				return fmt.Errorf("decompose resultX: %w", err)
			}
			outPtr += nbLimbs
			if err := decompose(resultY, uint(nbBits), outputs[outPtr:outPtr+nbLimbs]); err != nil {
				return fmt.Errorf("decompose resultY: %w", err)
			}
			outPtr += nbLimbs
			if err := decompose(resultZ, uint(nbBits), outputs[outPtr:outPtr+nbLimbs]); err != nil {
				return fmt.Errorf("decompose resultZ: %w", err)
			}
			outPtr += nbLimbs
			if err := decompose(accX, uint(nbBits), outputs[outPtr:outPtr+nbLimbs]); err != nil {
				return fmt.Errorf("decompose accX: %w", err)
			}
			outPtr += nbLimbs
			if err := decompose(accY, uint(nbBits), outputs[outPtr:outPtr+nbLimbs]); err != nil {
				return fmt.Errorf("decompose accY: %w", err)
			}
			outPtr += nbLimbs
			if err := decompose(accZ, uint(nbBits), outputs[outPtr:outPtr+nbLimbs]); err != nil {
				return fmt.Errorf("decompose accZ: %w", err)
			}
			outPtr += nbLimbs
		}
	}

	// now, we construct the sumcheck proof. For that we first need to compute
	// the challenges for computing the random linear combination of the
	// double-and-add outputs and for the claim polynomial evaluation.
	h, err := recursion.NewShort(mod, fp)
	if err != nil {
		return fmt.Errorf("new short hash: %w", err)
	}
	fs := cryptofs.NewTranscript(h, "alpha", "beta")
	for i := range xs {
		var P secp256k1.G1Affine
		var s fr_secp256k1.Element
		P.X.SetBigInt(xs[i])
		P.Y.SetBigInt(ys[i])
		raw := P.RawBytes()
		if err := fs.Bind("alpha", raw[:]); err != nil {
			return fmt.Errorf("bind alpha point: %w", err)
		}
		s.SetBigInt(scalars[i])
		if err := fs.Bind("alpha", s.Marshal()); err != nil {
			return fmt.Errorf("bind alpha scalar: %w", err)
		}
	}
	// challenges.
	// alpha is used for the random linear combination of the double-and-add
	alpha, err := fs.ComputeChallenge("alpha")
	if err != nil {
		return fmt.Errorf("compute challenge alpha: %w", err)
	}
	alphas := make([]*big.Int, 6)
	alphas[0] = big.NewInt(1)
	alphas[1] = new(big.Int).SetBytes(alpha)
	for i := 2; i < len(alphas); i++ {
		alphas[i] = new(big.Int).Mul(alphas[i-1], alphas[1])
	}

	// beta is used for the claim polynomial evaluation
	beta, err := fs.ComputeChallenge("beta")
	if err != nil {
		return fmt.Errorf("compute challenge beta: %w", err)
	}
	betas := make([]*big.Int, stdbits.Len(uint(nbInputs*scalarLength))-1)
	betas[0] = new(big.Int).SetBytes(beta)
	for i := 1; i < len(betas); i++ {
		betas[i] = new(big.Int).Mul(betas[i-1], betas[0])
	}

	nativeGate := dblAddSelectGate[*bigIntEngine, *big.Int]{folding: alphas}
	claim, evals, err := newNativeGate(fp, nativeGate, proofInput, [][]*big.Int{betas})
	if err != nil {
		return fmt.Errorf("new native gate: %w", err)
	}
	proof, err := prove(mod, fp, claim)
	if err != nil {
		return fmt.Errorf("prove: %w", err)
	}
	for _, pl := range proof.RoundPolyEvaluations {
		for j := range pl {
			if err := decompose(pl[j], uint(nbBits), outputs[outPtr:outPtr+nbLimbs]); err != nil {
				return fmt.Errorf("decompose claim: %w", err)
			}
			outPtr += nbLimbs
		}
	}
	// verifier computes the evaluation itself for consistency
	_ = evals
	return nil
}

func recompose(inputs []*big.Int, nbBits uint, res *big.Int) error {
	if len(inputs) == 0 {
		return fmt.Errorf("zero length slice input")
	}
	if res == nil {
		return fmt.Errorf("result not initialized")
	}
	res.SetUint64(0)
	for i := range inputs {
		res.Lsh(res, nbBits)
		res.Add(res, inputs[len(inputs)-i-1])
	}
	// TODO @gbotrel mod reduce ?
	return nil
}

func decompose(input *big.Int, nbBits uint, res []*big.Int) error {
	// limb modulus
	if input.BitLen() > len(res)*int(nbBits) {
		return fmt.Errorf("decomposed integer does not fit into res")
	}
	for _, r := range res {
		if r == nil {
			return fmt.Errorf("result slice element uninitalized")
		}
	}
	base := new(big.Int).Lsh(big.NewInt(1), nbBits)
	tmp := new(big.Int).Set(input)
	for i := 0; i < len(res); i++ {
		res[i].Mod(tmp, base)
		tmp.Rsh(tmp, nbBits)
	}
	return nil
}

func TestScalarMul(t *testing.T) {
	assert := test.NewAssert(t)
	type B = emparams.Secp256k1Fp
	type S = emparams.Secp256k1Fr
	var P secp256k1.G1Affine
	var s fr_secp256k1.Element
	nbInputs := 1 << 2
	nbScalarBits := 256
	scalarBound := new(big.Int).Lsh(big.NewInt(1), uint(nbScalarBits))
	points := make([]sw_emulated.AffinePoint[B], nbInputs)
	scalars := make([]emulated.Element[S], nbInputs)
	for i := range points {
		P.ScalarMultiplicationBase(big.NewInt(1))
		s.SetRandom()
		P.ScalarMultiplicationBase(s.BigInt(new(big.Int)))
		sc, _ := rand.Int(rand.Reader, scalarBound)
		// t.Log(P.X.String(), P.Y.String(), sc.String())
		points[i] = sw_emulated.AffinePoint[B]{
			X: emulated.ValueOf[B](P.X),
			Y: emulated.ValueOf[B](P.Y),
		}
		scalars[i] = emulated.ValueOf[S](sc)
	}
	circuit := ScalarMulCircuit[B, S]{
		Points:       make([]sw_emulated.AffinePoint[B], nbInputs),
		Scalars:      make([]emulated.Element[S], nbInputs),
		nbScalarBits: nbScalarBits,
	}
	witness := ScalarMulCircuit[B, S]{
		Points:  points,
		Scalars: scalars,
	}
	err := test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit)
}
