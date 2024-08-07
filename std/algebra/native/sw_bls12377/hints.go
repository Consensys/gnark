package sw_bls12377

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/constraint/solver"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		decomposeScalarG1,
		decomposeScalarG1Simple,
		decomposeScalarG2,
		doublePairingCheckHint,
		quadruplePairingCheckHint,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

func decomposeScalarG1Simple(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("expecting one input")
	}
	if len(outputs) != 2 {
		return fmt.Errorf("expecting two outputs")
	}
	cc := getInnerCurveConfig(scalarField)
	sp := ecc.SplitScalar(inputs[0], cc.glvBasis)
	outputs[0].Set(&(sp[0]))
	outputs[1].Set(&(sp[1]))

	return nil
}

func decomposeScalarG1(scalarField *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("expecting one input")
	}
	if len(outputs) != 3 {
		return fmt.Errorf("expecting three outputs")
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
		return fmt.Errorf("expecting one input")
	}
	if len(outputs) != 3 {
		return fmt.Errorf("expecting three outputs")
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

func doublePairingCheckHint(_ *big.Int, inputs, outputs []*big.Int) error {
	// This is inspired from https://eprint.iacr.org/2024/640.pdf
	// and based on a personal communication with the author Andrija Novakovic.
	var P0, P1 bls12377.G1Affine
	var Q0, Q1 bls12377.G2Affine

	P0.X.SetBigInt(inputs[0])
	P0.Y.SetBigInt(inputs[1])
	P1.X.SetBigInt(inputs[2])
	P1.Y.SetBigInt(inputs[3])
	Q0.X.A0.SetBigInt(inputs[4])
	Q0.X.A1.SetBigInt(inputs[5])
	Q0.Y.A0.SetBigInt(inputs[6])
	Q0.Y.A1.SetBigInt(inputs[7])
	Q1.X.A0.SetBigInt(inputs[8])
	Q1.X.A1.SetBigInt(inputs[9])
	Q1.Y.A0.SetBigInt(inputs[10])
	Q1.Y.A1.SetBigInt(inputs[11])

	lines0 := bls12377.PrecomputeLines(Q0)
	lines1 := bls12377.PrecomputeLines(Q1)
	millerLoop, err := bls12377.MillerLoopFixedQ(
		[]bls12377.G1Affine{P0, P1},
		[][2][len(bls12377.LoopCounter) - 1]bls12377.LineEvaluationAff{lines0, lines1},
	)
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

func quadruplePairingCheckHint(_ *big.Int, inputs, outputs []*big.Int) error {
	// This is inspired from https://eprint.iacr.org/2024/640.pdf
	// and based on a personal communication with the author Andrija Novakovic.
	var P0, P1, P2, P3 bls12377.G1Affine
	var Q0, Q1, Q2, Q3 bls12377.G2Affine

	P0.X.SetBigInt(inputs[0])
	P0.Y.SetBigInt(inputs[1])
	P1.X.SetBigInt(inputs[2])
	P1.Y.SetBigInt(inputs[3])
	P2.X.SetBigInt(inputs[4])
	P2.Y.SetBigInt(inputs[5])
	P3.X.SetBigInt(inputs[6])
	P3.Y.SetBigInt(inputs[7])
	Q0.X.A0.SetBigInt(inputs[8])
	Q0.X.A1.SetBigInt(inputs[9])
	Q0.Y.A0.SetBigInt(inputs[10])
	Q0.Y.A1.SetBigInt(inputs[11])
	Q1.X.A0.SetBigInt(inputs[12])
	Q1.X.A1.SetBigInt(inputs[13])
	Q1.Y.A0.SetBigInt(inputs[14])
	Q1.Y.A1.SetBigInt(inputs[15])
	Q2.X.A0.SetBigInt(inputs[16])
	Q2.X.A1.SetBigInt(inputs[17])
	Q2.Y.A0.SetBigInt(inputs[18])
	Q2.Y.A1.SetBigInt(inputs[19])
	Q3.X.A0.SetBigInt(inputs[20])
	Q3.X.A1.SetBigInt(inputs[21])
	Q3.Y.A0.SetBigInt(inputs[22])
	Q3.Y.A1.SetBigInt(inputs[23])

	lines0 := bls12377.PrecomputeLines(Q0)
	lines1 := bls12377.PrecomputeLines(Q1)
	lines2 := bls12377.PrecomputeLines(Q2)
	lines3 := bls12377.PrecomputeLines(Q3)
	millerLoop, err := bls12377.MillerLoopFixedQ(
		[]bls12377.G1Affine{P0, P1, P2, P3},
		[][2][len(bls12377.LoopCounter) - 1]bls12377.LineEvaluationAff{lines0, lines1, lines2, lines3},
	)
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
