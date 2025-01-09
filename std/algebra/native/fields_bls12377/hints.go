package fields_bls12377

import (
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/constraint/solver"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		divE2Hint,
		inverseE2Hint,
		inverseE6Hint,
		divE6Hint,
		inverseE12Hint,
		divE12Hint,
		finalExpHint,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

func inverseE2Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, c bls12377.E2

	a.A0.SetBigInt(inputs[0])
	a.A1.SetBigInt(inputs[1])

	c.Inverse(&a)

	c.A0.BigInt(res[0])
	c.A1.BigInt(res[1])

	return nil
}

func divE2Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, b, c bls12377.E2

	a.A0.SetBigInt(inputs[0])
	a.A1.SetBigInt(inputs[1])
	b.A0.SetBigInt(inputs[2])
	b.A1.SetBigInt(inputs[3])

	c.Inverse(&b).Mul(&c, &a)

	c.A0.BigInt(res[0])
	c.A1.BigInt(res[1])

	return nil
}

func divE6Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, b, c bls12377.E6

	a.B0.A0.SetBigInt(inputs[0])
	a.B1.A0.SetBigInt(inputs[1])
	a.B2.A0.SetBigInt(inputs[2])
	a.B0.A1.SetBigInt(inputs[3])
	a.B1.A1.SetBigInt(inputs[4])
	a.B2.A1.SetBigInt(inputs[5])

	b.B0.A0.SetBigInt(inputs[6])
	b.B1.A0.SetBigInt(inputs[7])
	b.B2.A0.SetBigInt(inputs[8])
	b.B0.A1.SetBigInt(inputs[9])
	b.B1.A1.SetBigInt(inputs[10])
	b.B2.A1.SetBigInt(inputs[11])

	c.Inverse(&b).Mul(&c, &a)

	c.B0.A0.BigInt(res[0])
	c.B1.A0.BigInt(res[1])
	c.B2.A0.BigInt(res[2])
	c.B0.A1.BigInt(res[3])
	c.B1.A1.BigInt(res[4])
	c.B2.A1.BigInt(res[5])

	return nil
}

func inverseE6Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, c bls12377.E6

	a.B0.A0.SetBigInt(inputs[0])
	a.B1.A0.SetBigInt(inputs[1])
	a.B2.A0.SetBigInt(inputs[2])
	a.B0.A1.SetBigInt(inputs[3])
	a.B1.A1.SetBigInt(inputs[4])
	a.B2.A1.SetBigInt(inputs[5])

	c.Inverse(&a)

	c.B0.A0.BigInt(res[0])
	c.B1.A0.BigInt(res[1])
	c.B2.A0.BigInt(res[2])
	c.B0.A1.BigInt(res[3])
	c.B1.A1.BigInt(res[4])
	c.B2.A1.BigInt(res[5])

	return nil
}

func divE12Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, b, c bls12377.E12

	a.C0.B0.A0.SetBigInt(inputs[0])
	a.C0.B1.A0.SetBigInt(inputs[1])
	a.C0.B2.A0.SetBigInt(inputs[2])
	a.C0.B0.A1.SetBigInt(inputs[3])
	a.C0.B1.A1.SetBigInt(inputs[4])
	a.C0.B2.A1.SetBigInt(inputs[5])
	a.C1.B0.A0.SetBigInt(inputs[6])
	a.C1.B1.A0.SetBigInt(inputs[7])
	a.C1.B2.A0.SetBigInt(inputs[8])
	a.C1.B0.A1.SetBigInt(inputs[9])
	a.C1.B1.A1.SetBigInt(inputs[10])
	a.C1.B2.A1.SetBigInt(inputs[11])

	b.C0.B0.A0.SetBigInt(inputs[12])
	b.C0.B1.A0.SetBigInt(inputs[13])
	b.C0.B2.A0.SetBigInt(inputs[14])
	b.C0.B0.A1.SetBigInt(inputs[15])
	b.C0.B1.A1.SetBigInt(inputs[16])
	b.C0.B2.A1.SetBigInt(inputs[17])
	b.C1.B0.A0.SetBigInt(inputs[18])
	b.C1.B1.A0.SetBigInt(inputs[19])
	b.C1.B2.A0.SetBigInt(inputs[20])
	b.C1.B0.A1.SetBigInt(inputs[21])
	b.C1.B1.A1.SetBigInt(inputs[22])
	b.C1.B2.A1.SetBigInt(inputs[23])

	c.Inverse(&b).Mul(&c, &a)

	c.C0.B0.A0.BigInt(res[0])
	c.C0.B1.A0.BigInt(res[1])
	c.C0.B2.A0.BigInt(res[2])
	c.C0.B0.A1.BigInt(res[3])
	c.C0.B1.A1.BigInt(res[4])
	c.C0.B2.A1.BigInt(res[5])
	c.C1.B0.A0.BigInt(res[6])
	c.C1.B1.A0.BigInt(res[7])
	c.C1.B2.A0.BigInt(res[8])
	c.C1.B0.A1.BigInt(res[9])
	c.C1.B1.A1.BigInt(res[10])
	c.C1.B2.A1.BigInt(res[11])

	return nil
}

func inverseE12Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, c bls12377.E12

	a.C0.B0.A0.SetBigInt(inputs[0])
	a.C0.B1.A0.SetBigInt(inputs[1])
	a.C0.B2.A0.SetBigInt(inputs[2])
	a.C0.B0.A1.SetBigInt(inputs[3])
	a.C0.B1.A1.SetBigInt(inputs[4])
	a.C0.B2.A1.SetBigInt(inputs[5])
	a.C1.B0.A0.SetBigInt(inputs[6])
	a.C1.B1.A0.SetBigInt(inputs[7])
	a.C1.B2.A0.SetBigInt(inputs[8])
	a.C1.B0.A1.SetBigInt(inputs[9])
	a.C1.B1.A1.SetBigInt(inputs[10])
	a.C1.B2.A1.SetBigInt(inputs[11])

	c.Inverse(&a)

	c.C0.B0.A0.BigInt(res[0])
	c.C0.B1.A0.BigInt(res[1])
	c.C0.B2.A0.BigInt(res[2])
	c.C0.B0.A1.BigInt(res[3])
	c.C0.B1.A1.BigInt(res[4])
	c.C0.B2.A1.BigInt(res[5])
	c.C1.B0.A0.BigInt(res[6])
	c.C1.B1.A0.BigInt(res[7])
	c.C1.B2.A0.BigInt(res[8])
	c.C1.B0.A1.BigInt(res[9])
	c.C1.B1.A1.BigInt(res[10])
	c.C1.B2.A1.BigInt(res[11])

	return nil
}

func finalExpHint(_ *big.Int, inputs, outputs []*big.Int) error {
	var millerLoop bls12377.E12

	millerLoop.C0.B0.A0.SetBigInt(inputs[0])
	millerLoop.C0.B0.A1.SetBigInt(inputs[1])
	millerLoop.C0.B1.A0.SetBigInt(inputs[2])
	millerLoop.C0.B1.A1.SetBigInt(inputs[3])
	millerLoop.C0.B2.A0.SetBigInt(inputs[4])
	millerLoop.C0.B2.A1.SetBigInt(inputs[5])
	millerLoop.C1.B0.A0.SetBigInt(inputs[6])
	millerLoop.C1.B0.A1.SetBigInt(inputs[7])
	millerLoop.C1.B1.A0.SetBigInt(inputs[8])
	millerLoop.C1.B1.A1.SetBigInt(inputs[9])
	millerLoop.C1.B2.A0.SetBigInt(inputs[10])
	millerLoop.C1.B2.A1.SetBigInt(inputs[11])

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
