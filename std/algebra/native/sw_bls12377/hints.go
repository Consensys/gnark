package sw_bls12377

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/constraint/solver"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		decomposeScalarG1,
		decomposeScalarG1Simple,
		decomposeScalarG2,
		scalarMulGLVG1Hint,
		scalarMulGLVG2Hint,
		jointScalarMulG1Hint,
		rationalReconstructExt,
		pairingCheckHint,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

func pairingCheckHint(scalarField *big.Int, inputs, outputs []*big.Int) error {
	var P bls12377.G1Affine
	var Q bls12377.G2Affine
	n := len(inputs)
	p := make([]bls12377.G1Affine, 0, n/6)
	q := make([]bls12377.G2Affine, 0, n/6)
	for k := 0; k < n/6+1; k += 2 {
		P.X.SetBigInt(inputs[k])
		P.Y.SetBigInt(inputs[k+1])
		p = append(p, P)
	}
	for k := n / 3; k < n/2+3; k += 4 {
		Q.X.A0.SetBigInt(inputs[k])
		Q.X.A1.SetBigInt(inputs[k+1])
		Q.Y.A0.SetBigInt(inputs[k+2])
		Q.Y.A1.SetBigInt(inputs[k+3])
		q = append(q, Q)
	}

	lines := make([][2][len(bls12377.LoopCounter) - 1]bls12377.LineEvaluationAff, 0, len(q))
	for _, qi := range q {
		lines = append(lines, bls12377.PrecomputeLines(qi))
	}
	millerLoop, err := bls12377.MillerLoopFixedQ(p, lines)
	if err != nil {
		return err
	}

	var root, rootPthInverse, residueWitness, scalingFactor bls12377.E12
	var exponent, exponentInv, finalExpFactor, polyFactor big.Int
	// polyFactor = 12(x-1)
	polyFactor.SetString("115033474957087604736", 10)
	// finalExpFactor = ((q^12 - 1) / r) / polyFactor
	finalExpFactor.SetString("92351561334497520756349650336409370070948672672207914824247073415859727964231807559847070685040742345026775319680739143654748316009031763764029886042408725311062057776702838555815712331129279611544378217895455619058809454575474763035923260395518532422855090028311239234310116353269618927871828693919559964406939845784130633021661399269804065961999062695977580539176029238189119059338698461832966347603096853909366901376879505972606045770762516580639801134008192256366142553202619529638202068488750102055204336502584141399828818871664747496033599618827160583206926869573005874449182200210044444351826855938563862937638034918413235278166699461287943529570559518592586872860190313088429391521694808994276205429071153237122495989095857292965461625387657577981811772819764071512345106346232882471034669258055302790607847924560040527682025558360106509628206144255667203317787586698694011876342903106644003067103035176245790275561392007119121995936066014208972135762663107247939004517852248103325700169848524693333524025685325993207375736519358185783520948988673594976115901587076295116293065682366935313875411927779217584729138600463438806153265891176654957439524358472291492028580820575807385461119025678550977847392818655362610734928283105671242634809807533919011078145", 10)

	// 1. get pth-root inverse
	exponent.Set(&finalExpFactor)
	root.Exp(millerLoop, &finalExpFactor)
	if root.IsOne() {
		rootPthInverse.SetOne()
	} else {
		exponentInv.ModInverse(&exponent, &polyFactor)
		exponent.Neg(&exponentInv).Mod(&exponent, &polyFactor)
		rootPthInverse.Exp(root, &exponent)
	}

	// 3. shift the Miller loop result so that millerLoop * scalingFactor
	// is of order finalExpFactor
	scalingFactor.Set(&rootPthInverse)
	millerLoop.Mul(&millerLoop, &scalingFactor)

	// 4. get the witness residue
	//
	// lambda = q - u, the optimal exponent
	var lambda big.Int
	lambda.SetString("258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139563774001527230824448", 10)
	exponent.ModInverse(&lambda, &finalExpFactor)
	residueWitness.Exp(millerLoop, &exponent)

	// return the witness residue
	residueWitness.C0.B0.A0.BigInt(outputs[0])
	residueWitness.C0.B0.A1.BigInt(outputs[1])
	residueWitness.C0.B1.A0.BigInt(outputs[2])
	residueWitness.C0.B1.A1.BigInt(outputs[3])
	residueWitness.C0.B2.A0.BigInt(outputs[4])
	residueWitness.C0.B2.A1.BigInt(outputs[5])
	residueWitness.C1.B0.A0.BigInt(outputs[6])
	residueWitness.C1.B0.A1.BigInt(outputs[7])
	residueWitness.C1.B1.A0.BigInt(outputs[8])
	residueWitness.C1.B1.A1.BigInt(outputs[9])
	residueWitness.C1.B2.A0.BigInt(outputs[10])
	residueWitness.C1.B2.A1.BigInt(outputs[11])

	// return the scaling factor
	scalingFactor.C0.B0.A0.BigInt(outputs[12])
	scalingFactor.C0.B0.A1.BigInt(outputs[13])
	scalingFactor.C0.B1.A0.BigInt(outputs[14])
	scalingFactor.C0.B1.A1.BigInt(outputs[15])
	scalingFactor.C0.B2.A0.BigInt(outputs[16])
	scalingFactor.C0.B2.A1.BigInt(outputs[17])

	return nil
}

func decomposeScalarG1Simple(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return errors.New("expecting one input")
	}
	if len(outputs) != 2 {
		return errors.New("expecting two outputs")
	}
	cc := getInnerCurveConfig(scalarField)
	sp := ecc.SplitScalar(inputs[0], cc.glvBasis)
	outputs[0].Set(&(sp[0]))
	outputs[1].Set(&(sp[1]))

	return nil
}

func decomposeScalarG1(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return errors.New("expecting one input")
	}
	if len(outputs) != 3 {
		return errors.New("expecting three outputs")
	}
	cc := getInnerCurveConfig(scalarField)
	sp := ecc.SplitScalar(inputs[0], cc.glvBasis)
	outputs[0].Set(&(sp[0]))
	outputs[1].Set(&(sp[1]))
	one := big.NewInt(1)
	// add (lambda+1, lambda) until scalar compostion is over Fr to ensure that
	// the high bits are set in decomposition.
	for outputs[0].Cmp(cc.lambda) < 1 && outputs[1].Cmp(cc.lambda) < 1 {
		outputs[0].Add(outputs[0], cc.lambda)
		outputs[0].Add(outputs[0], one)
		outputs[1].Add(outputs[1], cc.lambda)
	}
	// figure out how many times we have overflowed
	outputs[2].Mul(outputs[1], cc.lambda).Add(outputs[2], outputs[0])
	outputs[2].Sub(outputs[2], inputs[0])
	outputs[2].Div(outputs[2], cc.fr)

	return nil
}

func decomposeScalarG2(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return errors.New("expecting one input")
	}
	if len(outputs) != 3 {
		return errors.New("expecting three outputs")
	}
	cc := getInnerCurveConfig(scalarField)
	sp := ecc.SplitScalar(inputs[0], cc.glvBasis)
	outputs[0].Set(&(sp[0]))
	outputs[1].Set(&(sp[1]))
	one := big.NewInt(1)
	// add (lambda+1, lambda) until scalar compostion is over Fr to ensure that
	// the high bits are set in decomposition.
	for outputs[0].Cmp(cc.lambda) < 1 && outputs[1].Cmp(cc.lambda) < 1 {
		outputs[0].Add(outputs[0], cc.lambda)
		outputs[0].Add(outputs[0], one)
		outputs[1].Add(outputs[1], cc.lambda)
	}
	// figure out how many times we have overflowed
	outputs[2].Mul(outputs[1], cc.lambda).Add(outputs[2], outputs[0])
	outputs[2].Sub(outputs[2], inputs[0])
	outputs[2].Div(outputs[2], cc.fr)

	return nil
}

func scalarMulGLVG1Hint(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 3 {
		return errors.New("expecting three inputs")
	}
	if len(outputs) != 2 {
		return errors.New("expecting two outputs")
	}

	// compute the resulting point [s]Q
	var P bls12377.G1Affine
	P.X.SetBigInt(inputs[0])
	P.Y.SetBigInt(inputs[1])
	P.ScalarMultiplication(&P, inputs[2])
	P.X.BigInt(outputs[0])
	P.Y.BigInt(outputs[1])
	return nil
}

func jointScalarMulG1Hint(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 6 {
		return errors.New("expecting six inputs")
	}
	if len(outputs) != 2 {
		return errors.New("expecting two outputs")
	}

	// compute the resulting point [s]Q + [t]R
	var Q, R, result bls12377.G1Affine
	Q.X.SetBigInt(inputs[0])
	Q.Y.SetBigInt(inputs[1])
	R.X.SetBigInt(inputs[2])
	R.Y.SetBigInt(inputs[3])

	// handle infinity cases
	QIsInfinity := Q.X.IsZero() && Q.Y.IsZero()
	RIsInfinity := R.X.IsZero() && R.Y.IsZero()
	sIsZero := inputs[4].Sign() == 0
	tIsZero := inputs[5].Sign() == 0

	switch {
	case (QIsInfinity || sIsZero) && (RIsInfinity || tIsZero):
		// both contributions are zero
		outputs[0].SetInt64(0)
		outputs[1].SetInt64(0)
	case QIsInfinity || sIsZero:
		// only R contributes
		R.ScalarMultiplication(&R, inputs[5])
		R.X.BigInt(outputs[0])
		R.Y.BigInt(outputs[1])
	case RIsInfinity || tIsZero:
		// only Q contributes
		Q.ScalarMultiplication(&Q, inputs[4])
		Q.X.BigInt(outputs[0])
		Q.Y.BigInt(outputs[1])
	default:
		// both contribute
		Q.ScalarMultiplication(&Q, inputs[4])
		R.ScalarMultiplication(&R, inputs[5])
		result.Add(&Q, &R)
		result.X.BigInt(outputs[0])
		result.Y.BigInt(outputs[1])
	}
	return nil
}

func scalarMulGLVG2Hint(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 5 {
		return errors.New("expecting five inputs")
	}
	if len(outputs) != 4 {
		return errors.New("expecting four outputs")
	}

	// compute the resulting point [s]Q on G2
	var Q bls12377.G2Affine
	Q.X.A0.SetBigInt(inputs[0])
	Q.X.A1.SetBigInt(inputs[1])
	Q.Y.A0.SetBigInt(inputs[2])
	Q.Y.A1.SetBigInt(inputs[3])
	Q.ScalarMultiplication(&Q, inputs[4])
	Q.X.A0.BigInt(outputs[0])
	Q.X.A1.BigInt(outputs[1])
	Q.Y.A0.BigInt(outputs[2])
	Q.Y.A1.BigInt(outputs[3])
	return nil
}

func rationalReconstructExt(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two inputs")
	}
	if len(outputs) != 10 {
		return errors.New("expecting ten outputs")
	}
	cc := getInnerCurveConfig(scalarField)

	// Use lattice reduction to find (x, y, z, t) such that
	// k ≡ (x + λ*y) / (z + λ*t) (mod r)
	//
	// in-circuit we check that Q - [s]P = 0 or equivalently Q + [-s]P = 0
	// so here we use k = -s.
	//
	// With k = -s:
	// -s ≡ (x + λ*y) / (z + λ*t) (mod r)
	// s ≡ -(x + λ*y) / (z + λ*t) = (-x - λ*y) / (z + λ*t) (mod r)
	//
	// The circuit checks: s*(v1 + λ*v2) + u1 + λ*u2 ≡ 0 (mod r)
	// Rearranging: s ≡ -(u1 + λ*u2) / (v1 + λ*v2) (mod r)
	//
	// Matching: (-x - λ*y) = -(u1 + λ*u2)
	// So: u1 = x, u2 = y, v1 = z, v2 = t
	k := new(big.Int).Neg(inputs[0])
	k.Mod(k, cc.fr)
	rc := lattice.NewReconstructor(cc.fr).SetLambda(inputs[1])
	res := rc.RationalReconstructExt(k)
	x, y, z, t := res[0], res[1], res[2], res[3]

	// u1 = x, u2 = y, v1 = z, v2 = t
	outputs[0].Abs(x) // |u1| = |x|
	outputs[1].Abs(y) // |u2| = |y|
	outputs[2].Abs(z) // |v1| = |z|
	outputs[3].Abs(t) // |v2| = |t|

	// Compute overflow: q = (s*(v1 + λ*v2) + u1 + λ*u2) / r
	// Using signed values for the computation
	lambdaV2 := new(big.Int).Mul(inputs[1], t)
	vSum := new(big.Int).Add(z, lambdaV2)
	sTimesV := new(big.Int).Mul(inputs[0], vSum)
	lambdaU2 := new(big.Int).Mul(inputs[1], y)
	uSum := new(big.Int).Add(x, lambdaU2)
	outputs[4].Add(sTimesV, uSum)
	outputs[4].Div(outputs[4], cc.fr)
	// Capture the sign of q before taking absolute value
	qIsNeg := outputs[4].Sign() < 0
	outputs[4].Abs(outputs[4])

	// set the signs
	outputs[5].SetUint64(0) // isNegu1
	outputs[6].SetUint64(0) // isNegu2
	outputs[7].SetUint64(0) // isNegv1
	outputs[8].SetUint64(0) // isNegv2
	outputs[9].SetUint64(0) // isNegq

	// u1 = x is negative when x < 0
	if x.Sign() < 0 {
		outputs[5].SetUint64(1)
	}
	// u2 = y is negative when y < 0
	if y.Sign() < 0 {
		outputs[6].SetUint64(1)
	}
	// v1 = z is negative when z < 0
	if z.Sign() < 0 {
		outputs[7].SetUint64(1)
	}
	// v2 = t is negative when t < 0
	if t.Sign() < 0 {
		outputs[8].SetUint64(1)
	}
	// q sign (captured earlier)
	if qIsNeg {
		outputs[9].SetUint64(1)
	}

	return nil
}
