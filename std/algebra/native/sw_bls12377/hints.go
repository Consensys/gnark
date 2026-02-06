package sw_bls12377

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/field/eisenstein"
	"github.com/consensys/gnark/constraint/solver"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		decomposeScalarG1,
		decomposeScalarG1Simple,
		decomposeScalarG2,
		scalarMulGLVG1Hint,
		halfGCDEisenstein,
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

func halfGCDEisenstein(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two input")
	}
	if len(outputs) != 10 {
		return errors.New("expecting ten outputs")
	}
	cc := getInnerCurveConfig(scalarField)
	glvBasis := new(ecc.Lattice)
	ecc.PrecomputeLattice(cc.fr, inputs[1], glvBasis)
	r := eisenstein.ComplexNumber{
		A0: glvBasis.V1[0],
		A1: glvBasis.V1[1],
	}
	sp := ecc.SplitScalar(inputs[0], glvBasis)
	// in-circuit we check that Q - [s]P = 0 or equivalently Q + [-s]P = 0
	// so here we return -s instead of s.
	s := eisenstein.ComplexNumber{
		A0: sp[0],
		A1: sp[1],
	}
	s.Neg(&s)
	res := eisenstein.HalfGCD(&r, &s)
	outputs[0].Set(&res[0].A0)
	outputs[1].Set(&res[0].A1)
	outputs[2].Set(&res[1].A0)
	outputs[3].Set(&res[1].A1)
	outputs[4].Mul(&res[1].A1, inputs[1]).
		Add(outputs[4], &res[1].A0).
		Mul(outputs[4], inputs[0]).
		Add(outputs[4], &res[0].A0)
	s.A0.Mul(&res[0].A1, inputs[1])
	outputs[4].Add(outputs[4], &s.A0).
		Div(outputs[4], cc.fr)

	// set the signs
	outputs[5].SetUint64(0)
	outputs[6].SetUint64(0)
	outputs[7].SetUint64(0)
	outputs[8].SetUint64(0)
	outputs[9].SetUint64(0)

	if outputs[0].Sign() == -1 {
		outputs[0].Neg(outputs[0])
		outputs[5].SetUint64(1)
	}
	if outputs[1].Sign() == -1 {
		outputs[1].Neg(outputs[1])
		outputs[6].SetUint64(1)
	}
	if outputs[2].Sign() == -1 {
		outputs[2].Neg(outputs[2])
		outputs[7].SetUint64(1)
	}
	if outputs[3].Sign() == -1 {
		outputs[3].Neg(outputs[3])
		outputs[8].SetUint64(1)
	}
	if outputs[4].Sign() == -1 {
		outputs[4].Neg(outputs[4])
		outputs[9].SetUint64(1)
	}

	return nil
}
