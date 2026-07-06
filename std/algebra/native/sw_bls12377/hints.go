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
		decomposeScalarG1Simple,
		scalarMulGLVG1Hint,
		rationalReconstructExt,
		pairingCheckHint,
		pairingCheckTorusHint,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

// pairingCheckTorusHint computes the residue witness for torus-based pairing check
// The torus Miller loop computes ML^(p^6-1), so we need to adjust the hint accordingly
func pairingCheckTorusHint(scalarField *big.Int, inputs, outputs []*big.Int) error {
	// Input layout: 2 limbs per G1 (X, Y) + 4 limbs per G2 (X.A0, X.A1, Y.A0, Y.A1) = 6 limbs per pair
	n := len(inputs)
	if n%6 != 0 {
		return errors.New("invalid number of inputs for pairing check hint")
	}
	nPairs := n / 6

	var P bls12377.G1Affine
	var Q bls12377.G2Affine
	p := make([]bls12377.G1Affine, 0, nPairs)
	q := make([]bls12377.G2Affine, 0, nPairs)

	// Parse G1 points from indices [0, 2*nPairs)
	for k := 0; k < 2*nPairs; k += 2 {
		P.X.SetBigInt(inputs[k])
		P.Y.SetBigInt(inputs[k+1])
		p = append(p, P)
	}
	// Parse G2 points from indices [2*nPairs, 6*nPairs)
	for k := 2 * nPairs; k < 6*nPairs; k += 4 {
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

	// Apply p^6-1 to get to cyclotomic subgroup (this is what torus Miller loop does)
	var millerLoopCyclotomic bls12377.E12
	millerLoopCyclotomic.Conjugate(&millerLoop)
	millerLoop.Inverse(&millerLoop)
	millerLoopCyclotomic.Mul(&millerLoopCyclotomic, &millerLoop)

	// Now compute residue witness for (p^2+1)(p^4-p^2+1)/r part
	// Since we already applied p^6-1, the remaining exponent is (p^2+1)(p^4-p^2+1)/r
	var root, rootPthInverse, residueWitness, scalingFactor bls12377.E12
	var exponent, exponentInv, finalExpFactor, polyFactor big.Int
	// polyFactor = 12(x-1)
	polyFactor.SetString("115033474957087604736", 10)
	// finalExpFactor for (p^2+1)(p^4-p^2+1)/r part
	// This is ((q^12 - 1) / r) / (q^6 - 1) / polyFactor
	finalExpFactor.SetString("92351561334497520756349650336409370070948672672207914824247073415859727964231807559847070685040742345026775319680739143654748316009031763764029886042408725311062057776702838555815712331129279611544378217895455619058809454575474763035923260395518532422855090028311239234310116353269618927871828693919559964406939845784130633021661399269804065961999062695977580539176029238189119059338698461832966347603096853909366901376879505972606045770762516580639801134008192256366142553202619529638202068488750102055204336502584141399828818871664747496033599618827160583206926869573005874449182200210044444351826855938563862937638034918413235278166699461287943529570559518592586872860190313088429391521694808994276205429071153237122495989095857292965461625387657577981811772819764071512345106346232882471034669258055302790607847924560040527682025558360106509628206144255667203317787586698694011876342903106644003067103035176245790275561392007119121995936066014208972135762663107247939004517852248103325700169848524693333524025685325993207375736519358185783520948988673594976115901587076295116293065682366935313875411927779217584729138600463438806153265891176654957439524358472291492028580820575807385461119025678550977847392818655362610734928283105671242634809807533919011078145", 10)

	// 1. get pth-root inverse
	exponent.Set(&finalExpFactor)
	root.Exp(millerLoopCyclotomic, &finalExpFactor)
	if root.IsOne() {
		rootPthInverse.SetOne()
	} else {
		exponentInv.ModInverse(&exponent, &polyFactor)
		exponent.Neg(&exponentInv).Mod(&exponent, &polyFactor)
		rootPthInverse.Exp(root, &exponent)
	}

	// 3. shift the Miller loop result so that millerLoopCyclotomic * scalingFactor
	// is of order finalExpFactor
	scalingFactor.Set(&rootPthInverse)
	millerLoopCyclotomic.Mul(&millerLoopCyclotomic, &scalingFactor)

	// 4. get the witness residue
	// lambda = q - u, the optimal exponent
	var lambda big.Int
	lambda.SetString("258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139563774001527230824448", 10)
	exponent.ModInverse(&lambda, &finalExpFactor)
	residueWitness.Exp(millerLoopCyclotomic, &exponent)

	// Compute torus compression of residueWitness: y = C1 / (1 + C0)
	var torusWitness bls12377.E6
	var c0PlusOne bls12377.E6
	c0PlusOne.Set(&residueWitness.C0)
	var oneE6 bls12377.E6
	oneE6.SetOne()
	c0PlusOne.Add(&c0PlusOne, &oneE6)
	torusWitness.Inverse(&c0PlusOne)
	torusWitness.Mul(&torusWitness, &residueWitness.C1)

	// return the torus-compressed witness (6 elements)
	torusWitness.B0.A0.BigInt(outputs[0])
	torusWitness.B0.A1.BigInt(outputs[1])
	torusWitness.B1.A0.BigInt(outputs[2])
	torusWitness.B1.A1.BigInt(outputs[3])
	torusWitness.B2.A0.BigInt(outputs[4])
	torusWitness.B2.A1.BigInt(outputs[5])

	// return the scaling factor (6 elements, only C0 since it's in Fp6)
	scalingFactor.C0.B0.A0.BigInt(outputs[6])
	scalingFactor.C0.B0.A1.BigInt(outputs[7])
	scalingFactor.C0.B1.A0.BigInt(outputs[8])
	scalingFactor.C0.B1.A1.BigInt(outputs[9])
	scalingFactor.C0.B2.A0.BigInt(outputs[10])
	scalingFactor.C0.B2.A1.BigInt(outputs[11])

	return nil
}

func pairingCheckHint(scalarField *big.Int, inputs, outputs []*big.Int) error {
	var P bls12377.G1Affine
	var Q bls12377.G2Affine
	n := len(inputs)
	p := make([]bls12377.G1Affine, 0, n/6)
	q := make([]bls12377.G2Affine, 0, n/6)
	// first one-third is G1 points
	for k := 0; k < n/3; k += 2 {
		P.X.SetBigInt(inputs[k])
		P.Y.SetBigInt(inputs[k+1])
		p = append(p, P)
	}
	// subsequent two-thirds are G2 points
	for k := n / 3; k < n; k += 4 {
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

// rationalReconstructExt is the 4-D Eisenstein-style scalar decomposition for
// BLS12-377 G1's GLV+FakeGLV scalar mul, backed by LLL-based lattice rational
// reconstruction with proven Hermite bound |u_i|, |v_i| < γ₄·r^(1/4) ≈
// 1.25·r^(1/4). Replaces the older Eisenstein HalfGCD.
//
// Inputs: [s, λ] (scalar and GLV eigenvalue, both bounded by inner curve order).
// Outputs: [|u1|, |u2|, |v1|, |v2|, |q|, sign(u1), sign(u2), sign(v1), sign(v2), sign(q)] (10).
//
// The relation (in signed integers) is
//
//	s·(v1 + λ·v2) + u1 + λ·u2 = q·r
//
// where r is the inner curve order. The in-circuit check at sw_bls12377/g1.go::
// scalarMulGLVAndFakeGLV verifies this in the outer SNARK scalar field.
func rationalReconstructExt(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two inputs (s, λ)")
	}
	if len(outputs) != 10 {
		return errors.New("expecting ten outputs (4 abs values + 1 |q| + 5 sign bits)")
	}
	cc := getInnerCurveConfig(scalarField)

	// In-circuit we check Q − [s]P = 0, equivalently Q + [−s]P = 0, so we
	// negate the scalar before reconstruction (matches the previous convention).
	k := new(big.Int).Neg(inputs[0])
	k.Mod(k, cc.fr)

	rc := lattice.NewReconstructor(cc.fr).SetLambda(inputs[1])
	res := rc.RationalReconstructExt(k)
	// res = (x, y, z, t) with k = (x + λ·y)/(z + λ·t) mod r,
	// i.e., (x + λ·y) − k·(z + λ·t) ≡ 0 (mod r). With k = −s mod r this gives
	// (x + λ·y) + s·(z + λ·t) ≡ 0 (mod r). Mapping: u1 = x, u2 = y, v1 = z, v2 = t.
	u1 := new(big.Int).Set(res[0])
	u2 := new(big.Int).Set(res[1])
	v1 := new(big.Int).Set(res[2])
	v2 := new(big.Int).Set(res[3])

	// q = (s·(v1 + λ·v2) + u1 + λ·u2) / r computed in signed integers.
	q := new(big.Int).Mul(v2, inputs[1])
	q.Add(q, v1)
	q.Mul(q, inputs[0])
	tmp := new(big.Int).Mul(u2, inputs[1])
	q.Add(q, tmp)
	q.Add(q, u1)
	q.Quo(q, cc.fr)

	outputs[0].Abs(u1)
	outputs[1].Abs(u2)
	outputs[2].Abs(v1)
	outputs[3].Abs(v2)
	outputs[4].Abs(q)

	for i := 5; i <= 9; i++ {
		outputs[i].SetUint64(0)
	}
	if u1.Sign() < 0 {
		outputs[5].SetUint64(1)
	}
	if u2.Sign() < 0 {
		outputs[6].SetUint64(1)
	}
	if v1.Sign() < 0 {
		outputs[7].SetUint64(1)
	}
	if v2.Sign() < 0 {
		outputs[8].SetUint64(1)
	}
	if q.Sign() < 0 {
		outputs[9].SetUint64(1)
	}
	return nil
}
