package fields_bls12377

import (
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/constraint/solver"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		divE2Hint,
		divE6Hint,
		divE12Hint,
		inverseE2Hint,
		inverseE6Hint,
		inverseE12Hint,
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
	a.B0.A1.SetBigInt(inputs[1])
	a.B1.A0.SetBigInt(inputs[2])
	a.B1.A1.SetBigInt(inputs[3])
	a.B2.A0.SetBigInt(inputs[4])
	a.B2.A1.SetBigInt(inputs[5])

	b.B0.A0.SetBigInt(inputs[6])
	b.B0.A1.SetBigInt(inputs[7])
	b.B1.A0.SetBigInt(inputs[8])
	b.B1.A1.SetBigInt(inputs[9])
	b.B2.A0.SetBigInt(inputs[10])
	b.B2.A1.SetBigInt(inputs[11])

	c.Inverse(&b).Mul(&c, &a)

	c.B0.A0.BigInt(res[0])
	c.B0.A1.BigInt(res[1])
	c.B1.A0.BigInt(res[2])
	c.B1.A1.BigInt(res[3])
	c.B2.A0.BigInt(res[4])
	c.B2.A1.BigInt(res[5])

	return nil
}

func inverseE6Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, c bls12377.E6

	a.B0.A0.SetBigInt(inputs[0])
	a.B0.A1.SetBigInt(inputs[1])
	a.B1.A0.SetBigInt(inputs[2])
	a.B1.A1.SetBigInt(inputs[3])
	a.B2.A0.SetBigInt(inputs[4])
	a.B2.A1.SetBigInt(inputs[5])

	c.Inverse(&a)

	c.B0.A0.BigInt(res[0])
	c.B0.A1.BigInt(res[1])
	c.B1.A0.BigInt(res[2])
	c.B1.A1.BigInt(res[3])
	c.B2.A0.BigInt(res[4])
	c.B2.A1.BigInt(res[5])

	return nil
}

func divE12Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, b, c bls12377.E12

	a.C0.B0.A0.SetBigInt(inputs[0])
	a.C0.B0.A1.SetBigInt(inputs[1])
	a.C0.B1.A0.SetBigInt(inputs[2])
	a.C0.B1.A1.SetBigInt(inputs[3])
	a.C0.B2.A0.SetBigInt(inputs[4])
	a.C0.B2.A1.SetBigInt(inputs[5])
	a.C1.B0.A0.SetBigInt(inputs[6])
	a.C1.B0.A1.SetBigInt(inputs[7])
	a.C1.B1.A0.SetBigInt(inputs[8])
	a.C1.B1.A1.SetBigInt(inputs[9])
	a.C1.B2.A0.SetBigInt(inputs[10])
	a.C1.B2.A1.SetBigInt(inputs[11])

	b.C0.B0.A0.SetBigInt(inputs[12])
	b.C0.B0.A1.SetBigInt(inputs[13])
	b.C0.B1.A0.SetBigInt(inputs[14])
	b.C0.B1.A1.SetBigInt(inputs[15])
	b.C0.B2.A0.SetBigInt(inputs[16])
	b.C0.B2.A1.SetBigInt(inputs[17])
	b.C1.B0.A0.SetBigInt(inputs[18])
	b.C1.B0.A1.SetBigInt(inputs[19])
	b.C1.B1.A0.SetBigInt(inputs[20])
	b.C1.B1.A1.SetBigInt(inputs[21])
	b.C1.B2.A0.SetBigInt(inputs[22])
	b.C1.B2.A1.SetBigInt(inputs[23])

	c.Inverse(&b).Mul(&c, &a)

	c.C0.B0.A0.BigInt(res[0])
	c.C0.B0.A1.BigInt(res[1])
	c.C0.B1.A0.BigInt(res[2])
	c.C0.B1.A1.BigInt(res[3])
	c.C0.B2.A0.BigInt(res[4])
	c.C0.B2.A1.BigInt(res[5])
	c.C1.B0.A0.BigInt(res[6])
	c.C1.B0.A1.BigInt(res[7])
	c.C1.B1.A0.BigInt(res[8])
	c.C1.B1.A1.BigInt(res[9])
	c.C1.B2.A0.BigInt(res[10])
	c.C1.B2.A1.BigInt(res[11])

	return nil
}

func inverseE12Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, c bls12377.E12

	a.C0.B0.A0.SetBigInt(inputs[0])
	a.C0.B0.A1.SetBigInt(inputs[1])
	a.C0.B1.A0.SetBigInt(inputs[2])
	a.C0.B1.A1.SetBigInt(inputs[3])
	a.C0.B2.A0.SetBigInt(inputs[4])
	a.C0.B2.A1.SetBigInt(inputs[5])
	a.C1.B0.A0.SetBigInt(inputs[6])
	a.C1.B0.A1.SetBigInt(inputs[7])
	a.C1.B1.A0.SetBigInt(inputs[8])
	a.C1.B1.A1.SetBigInt(inputs[9])
	a.C1.B2.A0.SetBigInt(inputs[10])
	a.C1.B2.A1.SetBigInt(inputs[11])

	c.Inverse(&a)

	c.C0.B0.A0.BigInt(res[0])
	c.C0.B0.A1.BigInt(res[1])
	c.C0.B1.A0.BigInt(res[2])
	c.C0.B1.A1.BigInt(res[3])
	c.C0.B2.A0.BigInt(res[4])
	c.C0.B2.A1.BigInt(res[5])
	c.C1.B0.A0.BigInt(res[6])
	c.C1.B0.A1.BigInt(res[7])
	c.C1.B1.A0.BigInt(res[8])
	c.C1.B1.A1.BigInt(res[9])
	c.C1.B2.A0.BigInt(res[10])
	c.C1.B2.A1.BigInt(res[11])

	return nil
}

func finalExpHint(_ *big.Int, inputs, outputs []*big.Int) error {
	// This follows section 4.1 of https://eprint.iacr.org/2024/640.pdf (Th. 1)
	var millerLoop, residueWitness bls12377.E12
	var rInv big.Int

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

	// compute r-th root:
	// Exponentiate to rInv where
	// rInv = 1/r mod (p^12-1)/r
	rInv.SetString("10208748786837724877156759805239199917177088105850452097581398357781838343395535357717189281303817989030853426518402432972842003898131337328036123767288343472740290055992597327047843733820915319931789911460922332092893340406586659134897564792528992841360758317184371729851779228767022291575333619687450508149408291808665688425747351943672765401504532352302933193380323797562510328188696218527623617803336085522730402534476672219254656573543964081905263468361471236263414063051754798717965006033535737262535426559024265337552194770692912115634227850824349287678445075667227500062644865552196269410386640693498752691820776510255615212781349365166954324182425386812172284685207545357376138024103577229096125179210029150108085917426622002636460159193270457153824484424740291304472618370893768349010724508505559223070061402562692522679753894779470665228357312064233458448950731987606712484774731314132451528794596084167373606499619244419076763354699647800243598600024554183146018594109053978613659377521869110074983807776968064443737295525761159893356460041590615623520614511285178649677625190127954790028024727845772017830862600186003274909528270245217670645634670358694128233669703480796660621582552083085232238280068277127279315415621696399036462472389073266975782056160166232984523898881", 10)
	residueWitness.Exp(millerLoop, &rInv)

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

	return nil
}
