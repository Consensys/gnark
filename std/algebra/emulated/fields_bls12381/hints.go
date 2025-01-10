package fields_bls12381

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		// E2
		divE2Hint,
		inverseE2Hint,
		// E12
		divE12Hint,
		inverseE12Hint,
	}
}

func inverseE2Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, c bls12381.E2

			a.A0.SetBigInt(inputs[0])
			a.A1.SetBigInt(inputs[1])

			c.Inverse(&a)

			c.A0.BigInt(outputs[0])
			c.A1.BigInt(outputs[1])

			return nil
		})
}

func divE2Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, b, c bls12381.E2

			a.A0.SetBigInt(inputs[0])
			a.A1.SetBigInt(inputs[1])
			b.A0.SetBigInt(inputs[2])
			b.A1.SetBigInt(inputs[3])

			c.Inverse(&b).Mul(&c, &a)

			c.A0.BigInt(outputs[0])
			c.A1.BigInt(outputs[1])

			return nil
		})
}

// E12 hints
func inverseE12Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, c bls12381.E12

			var d [12]big.Int
			d[0].Add(inputs[0], inputs[6])
			d[1].Set(inputs[6])
			d[2].Add(inputs[2], inputs[8])
			d[3].Set(inputs[8])
			d[4].Add(inputs[4], inputs[10])
			d[5].Set(inputs[10])
			d[6].Add(inputs[1], inputs[7])
			d[7].Set(inputs[7])
			d[8].Add(inputs[3], inputs[9])
			d[9].Set(inputs[9])
			d[10].Add(inputs[5], inputs[11])
			d[11].Set(inputs[11])
			a.C0.B0.A0.SetBigInt(&d[0])
			a.C0.B0.A1.SetBigInt(&d[1])
			a.C0.B1.A0.SetBigInt(&d[2])
			a.C0.B1.A1.SetBigInt(&d[3])
			a.C0.B2.A0.SetBigInt(&d[4])
			a.C0.B2.A1.SetBigInt(&d[5])
			a.C1.B0.A0.SetBigInt(&d[6])
			a.C1.B0.A1.SetBigInt(&d[7])
			a.C1.B1.A0.SetBigInt(&d[8])
			a.C1.B1.A1.SetBigInt(&d[9])
			a.C1.B2.A0.SetBigInt(&d[10])
			a.C1.B2.A1.SetBigInt(&d[11])

			c.Inverse(&a)

			var c0, c1, c2, c3, c4, c5 fp.Element
			c0.Sub(&c.C0.B0.A0, &c.C0.B0.A1)
			c1.Sub(&c.C1.B0.A0, &c.C1.B0.A1)
			c2.Sub(&c.C0.B1.A0, &c.C0.B1.A1)
			c3.Sub(&c.C1.B1.A0, &c.C1.B1.A1)
			c4.Sub(&c.C0.B2.A0, &c.C0.B2.A1)
			c5.Sub(&c.C1.B2.A0, &c.C1.B2.A1)

			c0.BigInt(outputs[0])
			c1.BigInt(outputs[1])
			c2.BigInt(outputs[2])
			c3.BigInt(outputs[3])
			c4.BigInt(outputs[4])
			c5.BigInt(outputs[5])
			c.C0.B0.A1.BigInt(outputs[6])
			c.C1.B0.A1.BigInt(outputs[7])
			c.C0.B1.A1.BigInt(outputs[8])
			c.C1.B1.A1.BigInt(outputs[9])
			c.C0.B2.A1.BigInt(outputs[10])
			c.C1.B2.A1.BigInt(outputs[11])

			return nil
		})
}

func divE12Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, b, c bls12381.E12

			var d [12]big.Int
			d[0].Add(inputs[0], inputs[6])
			d[1].Set(inputs[6])
			d[2].Add(inputs[2], inputs[8])
			d[3].Set(inputs[8])
			d[4].Add(inputs[4], inputs[10])
			d[5].Set(inputs[10])
			d[6].Add(inputs[1], inputs[7])
			d[7].Set(inputs[7])
			d[8].Add(inputs[3], inputs[9])
			d[9].Set(inputs[9])
			d[10].Add(inputs[5], inputs[11])
			d[11].Set(inputs[11])
			a.C0.B0.A0.SetBigInt(&d[0])
			a.C0.B0.A1.SetBigInt(&d[1])
			a.C0.B1.A0.SetBigInt(&d[2])
			a.C0.B1.A1.SetBigInt(&d[3])
			a.C0.B2.A0.SetBigInt(&d[4])
			a.C0.B2.A1.SetBigInt(&d[5])
			a.C1.B0.A0.SetBigInt(&d[6])
			a.C1.B0.A1.SetBigInt(&d[7])
			a.C1.B1.A0.SetBigInt(&d[8])
			a.C1.B1.A1.SetBigInt(&d[9])
			a.C1.B2.A0.SetBigInt(&d[10])
			a.C1.B2.A1.SetBigInt(&d[11])

			d[0].Add(inputs[12], inputs[18])
			d[1].Set(inputs[18])
			d[2].Add(inputs[14], inputs[20])
			d[3].Set(inputs[20])
			d[4].Add(inputs[16], inputs[22])
			d[5].Set(inputs[22])
			d[6].Add(inputs[13], inputs[19])
			d[7].Set(inputs[19])
			d[8].Add(inputs[15], inputs[21])
			d[9].Set(inputs[21])
			d[10].Add(inputs[17], inputs[23])
			d[11].Set(inputs[23])
			b.C0.B0.A0.SetBigInt(&d[0])
			b.C0.B0.A1.SetBigInt(&d[1])
			b.C0.B1.A0.SetBigInt(&d[2])
			b.C0.B1.A1.SetBigInt(&d[3])
			b.C0.B2.A0.SetBigInt(&d[4])
			b.C0.B2.A1.SetBigInt(&d[5])
			b.C1.B0.A0.SetBigInt(&d[6])
			b.C1.B0.A1.SetBigInt(&d[7])
			b.C1.B1.A0.SetBigInt(&d[8])
			b.C1.B1.A1.SetBigInt(&d[9])
			b.C1.B2.A0.SetBigInt(&d[10])
			b.C1.B2.A1.SetBigInt(&d[11])

			c.Inverse(&b).Mul(&c, &a)

			var c0, c1, c2, c3, c4, c5 fp.Element
			c0.Sub(&c.C0.B0.A0, &c.C0.B0.A1)
			c1.Sub(&c.C1.B0.A0, &c.C1.B0.A1)
			c2.Sub(&c.C0.B1.A0, &c.C0.B1.A1)
			c3.Sub(&c.C1.B1.A0, &c.C1.B1.A1)
			c4.Sub(&c.C0.B2.A0, &c.C0.B2.A1)
			c5.Sub(&c.C1.B2.A0, &c.C1.B2.A1)

			c0.BigInt(outputs[0])
			c1.BigInt(outputs[1])
			c2.BigInt(outputs[2])
			c3.BigInt(outputs[3])
			c4.BigInt(outputs[4])
			c5.BigInt(outputs[5])
			c.C0.B0.A1.BigInt(outputs[6])
			c.C1.B0.A1.BigInt(outputs[7])
			c.C0.B1.A1.BigInt(outputs[8])
			c.C1.B1.A1.BigInt(outputs[9])
			c.C0.B2.A1.BigInt(outputs[10])
			c.C1.B2.A1.BigInt(outputs[11])

			return nil
		})
}
