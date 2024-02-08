package fields_bls24315

import (
	"math/big"

	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/constraint/solver"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		divE2Hint,
		divE4Hint,
		divE12Hint,
		divE24Hint,
		inverseE2Hint,
		inverseE4Hint,
		inverseE12Hint,
		inverseE24Hint,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

var inverseE2Hint = func(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, c bls24315.E2

	a.A0.SetBigInt(inputs[0])
	a.A1.SetBigInt(inputs[1])

	c.Inverse(&a)

	c.A0.BigInt(res[0])
	c.A1.BigInt(res[1])

	return nil
}

func divE2Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, b, c bls24315.E2

	a.A0.SetBigInt(inputs[0])
	a.A1.SetBigInt(inputs[1])
	b.A0.SetBigInt(inputs[2])
	b.A1.SetBigInt(inputs[3])

	c.Inverse(&b).Mul(&c, &a)

	c.A0.BigInt(res[0])
	c.A1.BigInt(res[1])

	return nil
}

func divE4Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, b, c bls24315.E4

	a.B0.A0.SetBigInt(inputs[0])
	a.B0.A1.SetBigInt(inputs[1])
	a.B1.A0.SetBigInt(inputs[2])
	a.B1.A1.SetBigInt(inputs[3])
	b.B0.A0.SetBigInt(inputs[4])
	b.B0.A1.SetBigInt(inputs[5])
	b.B1.A0.SetBigInt(inputs[6])
	b.B1.A1.SetBigInt(inputs[7])

	c.Inverse(&b).Mul(&c, &a)

	c.B0.A0.BigInt(res[0])
	c.B0.A1.BigInt(res[1])
	c.B1.A0.BigInt(res[2])
	c.B1.A1.BigInt(res[3])

	return nil
}

func inverseE4Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, c bls24315.E4

	a.B0.A0.SetBigInt(inputs[0])
	a.B0.A1.SetBigInt(inputs[1])
	a.B1.A0.SetBigInt(inputs[2])
	a.B1.A1.SetBigInt(inputs[3])

	c.Inverse(&a)

	c.B0.A0.BigInt(res[0])
	c.B0.A1.BigInt(res[1])
	c.B1.A0.BigInt(res[2])
	c.B1.A1.BigInt(res[3])

	return nil
}

func divE12Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, b, c bls24315.E12

	a.C0.B0.A0.SetBigInt(inputs[0])
	a.C0.B0.A1.SetBigInt(inputs[1])
	a.C0.B1.A0.SetBigInt(inputs[2])
	a.C0.B1.A1.SetBigInt(inputs[3])
	a.C1.B0.A0.SetBigInt(inputs[4])
	a.C1.B0.A1.SetBigInt(inputs[5])
	a.C1.B1.A0.SetBigInt(inputs[6])
	a.C1.B1.A1.SetBigInt(inputs[7])
	a.C2.B0.A0.SetBigInt(inputs[8])
	a.C2.B0.A1.SetBigInt(inputs[9])
	a.C2.B1.A0.SetBigInt(inputs[10])
	a.C2.B1.A1.SetBigInt(inputs[11])

	b.C0.B0.A0.SetBigInt(inputs[12])
	b.C0.B0.A1.SetBigInt(inputs[13])
	b.C0.B1.A0.SetBigInt(inputs[14])
	b.C0.B1.A1.SetBigInt(inputs[15])
	b.C1.B0.A0.SetBigInt(inputs[16])
	b.C1.B0.A1.SetBigInt(inputs[17])
	b.C1.B1.A0.SetBigInt(inputs[18])
	b.C1.B1.A1.SetBigInt(inputs[19])
	b.C2.B0.A0.SetBigInt(inputs[20])
	b.C2.B0.A1.SetBigInt(inputs[21])
	b.C2.B1.A0.SetBigInt(inputs[22])
	b.C2.B1.A1.SetBigInt(inputs[23])

	c.Inverse(&b).Mul(&c, &a)

	c.C0.B0.A0.BigInt(res[0])
	c.C0.B0.A1.BigInt(res[1])
	c.C0.B1.A0.BigInt(res[2])
	c.C0.B1.A1.BigInt(res[3])
	c.C1.B0.A0.BigInt(res[4])
	c.C1.B0.A1.BigInt(res[5])
	c.C1.B1.A0.BigInt(res[6])
	c.C1.B1.A1.BigInt(res[7])
	c.C2.B0.A0.BigInt(res[8])
	c.C2.B0.A1.BigInt(res[9])
	c.C2.B1.A0.BigInt(res[10])
	c.C2.B1.A1.BigInt(res[11])

	return nil
}

func inverseE12Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, c bls24315.E12

	a.C0.B0.A0.SetBigInt(inputs[0])
	a.C0.B0.A1.SetBigInt(inputs[1])
	a.C0.B1.A0.SetBigInt(inputs[2])
	a.C0.B1.A1.SetBigInt(inputs[3])
	a.C1.B0.A0.SetBigInt(inputs[4])
	a.C1.B0.A1.SetBigInt(inputs[5])
	a.C1.B1.A0.SetBigInt(inputs[6])
	a.C1.B1.A1.SetBigInt(inputs[7])
	a.C2.B0.A0.SetBigInt(inputs[8])
	a.C2.B0.A1.SetBigInt(inputs[9])
	a.C2.B1.A0.SetBigInt(inputs[10])
	a.C2.B1.A1.SetBigInt(inputs[11])

	c.Inverse(&a)

	c.C0.B0.A0.BigInt(res[0])
	c.C0.B0.A1.BigInt(res[1])
	c.C0.B1.A0.BigInt(res[2])
	c.C0.B1.A1.BigInt(res[3])
	c.C1.B0.A0.BigInt(res[4])
	c.C1.B0.A1.BigInt(res[5])
	c.C1.B1.A0.BigInt(res[6])
	c.C1.B1.A1.BigInt(res[7])
	c.C2.B0.A0.BigInt(res[8])
	c.C2.B0.A1.BigInt(res[9])
	c.C2.B1.A0.BigInt(res[10])
	c.C2.B1.A1.BigInt(res[11])

	return nil
}

func divE24Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, b, c bls24315.E24

	a.D0.C0.B0.A0.SetBigInt(inputs[0])
	a.D0.C0.B0.A1.SetBigInt(inputs[1])
	a.D0.C0.B1.A0.SetBigInt(inputs[2])
	a.D0.C0.B1.A1.SetBigInt(inputs[3])
	a.D0.C1.B0.A0.SetBigInt(inputs[4])
	a.D0.C1.B0.A1.SetBigInt(inputs[5])
	a.D0.C1.B1.A0.SetBigInt(inputs[6])
	a.D0.C1.B1.A1.SetBigInt(inputs[7])
	a.D0.C2.B0.A0.SetBigInt(inputs[8])
	a.D0.C2.B0.A1.SetBigInt(inputs[9])
	a.D0.C2.B1.A0.SetBigInt(inputs[10])
	a.D0.C2.B1.A1.SetBigInt(inputs[11])
	a.D1.C0.B0.A0.SetBigInt(inputs[12])
	a.D1.C0.B0.A1.SetBigInt(inputs[13])
	a.D1.C0.B1.A0.SetBigInt(inputs[14])
	a.D1.C0.B1.A1.SetBigInt(inputs[15])
	a.D1.C1.B0.A0.SetBigInt(inputs[16])
	a.D1.C1.B0.A1.SetBigInt(inputs[17])
	a.D1.C1.B1.A0.SetBigInt(inputs[18])
	a.D1.C1.B1.A1.SetBigInt(inputs[19])
	a.D1.C2.B0.A0.SetBigInt(inputs[20])
	a.D1.C2.B0.A1.SetBigInt(inputs[21])
	a.D1.C2.B1.A0.SetBigInt(inputs[22])
	a.D1.C2.B1.A1.SetBigInt(inputs[23])

	b.D0.C0.B0.A0.SetBigInt(inputs[24])
	b.D0.C0.B0.A1.SetBigInt(inputs[25])
	b.D0.C0.B1.A0.SetBigInt(inputs[26])
	b.D0.C0.B1.A1.SetBigInt(inputs[27])
	b.D0.C1.B0.A0.SetBigInt(inputs[28])
	b.D0.C1.B0.A1.SetBigInt(inputs[29])
	b.D0.C1.B1.A0.SetBigInt(inputs[30])
	b.D0.C1.B1.A1.SetBigInt(inputs[31])
	b.D0.C2.B0.A0.SetBigInt(inputs[32])
	b.D0.C2.B0.A1.SetBigInt(inputs[33])
	b.D0.C2.B1.A0.SetBigInt(inputs[34])
	b.D0.C2.B1.A1.SetBigInt(inputs[35])
	b.D1.C0.B0.A0.SetBigInt(inputs[36])
	b.D1.C0.B0.A1.SetBigInt(inputs[37])
	b.D1.C0.B1.A0.SetBigInt(inputs[38])
	b.D1.C0.B1.A1.SetBigInt(inputs[39])
	b.D1.C1.B0.A0.SetBigInt(inputs[40])
	b.D1.C1.B0.A1.SetBigInt(inputs[41])
	b.D1.C1.B1.A0.SetBigInt(inputs[42])
	b.D1.C1.B1.A1.SetBigInt(inputs[43])
	b.D1.C2.B0.A0.SetBigInt(inputs[44])
	b.D1.C2.B0.A1.SetBigInt(inputs[45])
	b.D1.C2.B1.A0.SetBigInt(inputs[46])
	b.D1.C2.B1.A1.SetBigInt(inputs[47])

	c.Inverse(&b).Mul(&c, &a)

	c.D0.C0.B0.A0.BigInt(res[0])
	c.D0.C0.B0.A1.BigInt(res[1])
	c.D0.C0.B1.A0.BigInt(res[2])
	c.D0.C0.B1.A1.BigInt(res[3])
	c.D0.C1.B0.A0.BigInt(res[4])
	c.D0.C1.B0.A1.BigInt(res[5])
	c.D0.C1.B1.A0.BigInt(res[6])
	c.D0.C1.B1.A1.BigInt(res[7])
	c.D0.C2.B0.A0.BigInt(res[8])
	c.D0.C2.B0.A1.BigInt(res[9])
	c.D0.C2.B1.A0.BigInt(res[10])
	c.D0.C2.B1.A1.BigInt(res[11])
	c.D1.C0.B0.A0.BigInt(res[12])
	c.D1.C0.B0.A1.BigInt(res[13])
	c.D1.C0.B1.A0.BigInt(res[14])
	c.D1.C0.B1.A1.BigInt(res[15])
	c.D1.C1.B0.A0.BigInt(res[16])
	c.D1.C1.B0.A1.BigInt(res[17])
	c.D1.C1.B1.A0.BigInt(res[18])
	c.D1.C1.B1.A1.BigInt(res[19])
	c.D1.C2.B0.A0.BigInt(res[20])
	c.D1.C2.B0.A1.BigInt(res[21])
	c.D1.C2.B1.A0.BigInt(res[22])
	c.D1.C2.B1.A1.BigInt(res[23])

	return nil
}

func inverseE24Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, c bls24315.E24

	a.D0.C0.B0.A0.SetBigInt(inputs[0])
	a.D0.C0.B0.A1.SetBigInt(inputs[1])
	a.D0.C0.B1.A0.SetBigInt(inputs[2])
	a.D0.C0.B1.A1.SetBigInt(inputs[3])
	a.D0.C1.B0.A0.SetBigInt(inputs[4])
	a.D0.C1.B0.A1.SetBigInt(inputs[5])
	a.D0.C1.B1.A0.SetBigInt(inputs[6])
	a.D0.C1.B1.A1.SetBigInt(inputs[7])
	a.D0.C2.B0.A0.SetBigInt(inputs[8])
	a.D0.C2.B0.A1.SetBigInt(inputs[9])
	a.D0.C2.B1.A0.SetBigInt(inputs[10])
	a.D0.C2.B1.A1.SetBigInt(inputs[11])
	a.D1.C0.B0.A0.SetBigInt(inputs[12])
	a.D1.C0.B0.A1.SetBigInt(inputs[13])
	a.D1.C0.B1.A0.SetBigInt(inputs[14])
	a.D1.C0.B1.A1.SetBigInt(inputs[15])
	a.D1.C1.B0.A0.SetBigInt(inputs[16])
	a.D1.C1.B0.A1.SetBigInt(inputs[17])
	a.D1.C1.B1.A0.SetBigInt(inputs[18])
	a.D1.C1.B1.A1.SetBigInt(inputs[19])
	a.D1.C2.B0.A0.SetBigInt(inputs[20])
	a.D1.C2.B0.A1.SetBigInt(inputs[21])
	a.D1.C2.B1.A0.SetBigInt(inputs[22])
	a.D1.C2.B1.A1.SetBigInt(inputs[23])

	c.Inverse(&a)

	c.D0.C0.B0.A0.BigInt(res[0])
	c.D0.C0.B0.A1.BigInt(res[1])
	c.D0.C0.B1.A0.BigInt(res[2])
	c.D0.C0.B1.A1.BigInt(res[3])
	c.D0.C1.B0.A0.BigInt(res[4])
	c.D0.C1.B0.A1.BigInt(res[5])
	c.D0.C1.B1.A0.BigInt(res[6])
	c.D0.C1.B1.A1.BigInt(res[7])
	c.D0.C2.B0.A0.BigInt(res[8])
	c.D0.C2.B0.A1.BigInt(res[9])
	c.D0.C2.B1.A0.BigInt(res[10])
	c.D0.C2.B1.A1.BigInt(res[11])
	c.D1.C0.B0.A0.BigInt(res[12])
	c.D1.C0.B0.A1.BigInt(res[13])
	c.D1.C0.B1.A0.BigInt(res[14])
	c.D1.C0.B1.A1.BigInt(res[15])
	c.D1.C1.B0.A0.BigInt(res[16])
	c.D1.C1.B0.A1.BigInt(res[17])
	c.D1.C1.B1.A0.BigInt(res[18])
	c.D1.C1.B1.A1.BigInt(res[19])
	c.D1.C2.B0.A0.BigInt(res[20])
	c.D1.C2.B0.A1.BigInt(res[21])
	c.D1.C2.B1.A0.BigInt(res[22])
	c.D1.C2.B1.A1.BigInt(res[23])

	return nil
}
