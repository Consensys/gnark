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
		// E6
		divE6Hint,
		inverseE6Hint,
		squareTorusHint,
		divE6By6Hint,
		// E12
		divE12Hint,
		inverseE12Hint,
		finalExpHint,
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

// E6 hints
func inverseE6Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, c bls12381.E6

			a.B0.A0.SetBigInt(inputs[0])
			a.B0.A1.SetBigInt(inputs[1])
			a.B1.A0.SetBigInt(inputs[2])
			a.B1.A1.SetBigInt(inputs[3])
			a.B2.A0.SetBigInt(inputs[4])
			a.B2.A1.SetBigInt(inputs[5])

			c.Inverse(&a)

			c.B0.A0.BigInt(outputs[0])
			c.B0.A1.BigInt(outputs[1])
			c.B1.A0.BigInt(outputs[2])
			c.B1.A1.BigInt(outputs[3])
			c.B2.A0.BigInt(outputs[4])
			c.B2.A1.BigInt(outputs[5])

			return nil
		})
}

func divE6Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, b, c bls12381.E6

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

			c.B0.A0.BigInt(outputs[0])
			c.B0.A1.BigInt(outputs[1])
			c.B1.A0.BigInt(outputs[2])
			c.B1.A1.BigInt(outputs[3])
			c.B2.A0.BigInt(outputs[4])
			c.B2.A1.BigInt(outputs[5])

			return nil
		})
}

func squareTorusHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, c bls12381.E6

			a.B0.A0.SetBigInt(inputs[0])
			a.B0.A1.SetBigInt(inputs[1])
			a.B1.A0.SetBigInt(inputs[2])
			a.B1.A1.SetBigInt(inputs[3])
			a.B2.A0.SetBigInt(inputs[4])
			a.B2.A1.SetBigInt(inputs[5])

			_c := a.DecompressTorus()
			_c.CyclotomicSquare(&_c)
			c, _ = _c.CompressTorus()

			c.B0.A0.BigInt(outputs[0])
			c.B0.A1.BigInt(outputs[1])
			c.B1.A0.BigInt(outputs[2])
			c.B1.A1.BigInt(outputs[3])
			c.B2.A0.BigInt(outputs[4])
			c.B2.A1.BigInt(outputs[5])

			return nil
		})
}

func divE6By6Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, c bls12381.E6

			a.B0.A0.SetBigInt(inputs[0])
			a.B0.A1.SetBigInt(inputs[1])
			a.B1.A0.SetBigInt(inputs[2])
			a.B1.A1.SetBigInt(inputs[3])
			a.B2.A0.SetBigInt(inputs[4])
			a.B2.A1.SetBigInt(inputs[5])

			var sixInv fp.Element
			sixInv.SetString("6")
			sixInv.Inverse(&sixInv)
			c.B0.MulByElement(&a.B0, &sixInv)
			c.B1.MulByElement(&a.B1, &sixInv)
			c.B2.MulByElement(&a.B2, &sixInv)

			c.B0.A0.BigInt(outputs[0])
			c.B0.A1.BigInt(outputs[1])
			c.B1.A0.BigInt(outputs[2])
			c.B1.A1.BigInt(outputs[3])
			c.B2.A0.BigInt(outputs[4])
			c.B2.A1.BigInt(outputs[5])

			return nil
		})
}

// E12 hints
func inverseE12Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, c bls12381.E12

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

			c.C0.B0.A0.BigInt(outputs[0])
			c.C0.B0.A1.BigInt(outputs[1])
			c.C0.B1.A0.BigInt(outputs[2])
			c.C0.B1.A1.BigInt(outputs[3])
			c.C0.B2.A0.BigInt(outputs[4])
			c.C0.B2.A1.BigInt(outputs[5])
			c.C1.B0.A0.BigInt(outputs[6])
			c.C1.B0.A1.BigInt(outputs[7])
			c.C1.B1.A0.BigInt(outputs[8])
			c.C1.B1.A1.BigInt(outputs[9])
			c.C1.B2.A0.BigInt(outputs[10])
			c.C1.B2.A1.BigInt(outputs[11])

			return nil
		})
}

func divE12Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, b, c bls12381.E12

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

			c.C0.B0.A0.BigInt(outputs[0])
			c.C0.B0.A1.BigInt(outputs[1])
			c.C0.B1.A0.BigInt(outputs[2])
			c.C0.B1.A1.BigInt(outputs[3])
			c.C0.B2.A0.BigInt(outputs[4])
			c.C0.B2.A1.BigInt(outputs[5])
			c.C1.B0.A0.BigInt(outputs[6])
			c.C1.B0.A1.BigInt(outputs[7])
			c.C1.B1.A0.BigInt(outputs[8])
			c.C1.B1.A1.BigInt(outputs[9])
			c.C1.B2.A0.BigInt(outputs[10])
			c.C1.B2.A1.BigInt(outputs[11])

			return nil
		})
}

func finalExpHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	// This follows section 4.1 of https://eprint.iacr.org/2024/640.pdf (Th. 1)
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var millerLoop, residueWitness bls12381.E12
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
			rInv.SetString("169662389312441398885310937191698694666993326870281216192803558492181163400934408837135364582394949149589560242411491538960982200559697133935443307582773537814554128992403254243871087441488619811839498788505657962013599019994544063402394719913759780901881538869078447034832302535303591303383830742161317593225991746471557492001710830538428792119562309446698444646787667517629943447802199824630112988907247336627481159245442124709621313522294197747687500252452962523217400829932174349352696726049683687654879009114460723993703760367089269403767790334911644010940272722630305066645230222732316445557889124653426141642271480304669447694344127599708992364443461893123938202386892312748211835322692697497854107961493711137028209148238339237355911496376520814450515612396561384525661635220451168152178239892009375229296874955612623691164738926395993739297557487207643426168321070539996994036837992284584225139752716615623194417718962478029165908544042568334172107008712033983002554672734519081879196926275059798317879322062358113986901925780890205936071364647548199159506709147492864081514759663116291487638998943660232689862634717010538047493292265992334130695994203833154950619462266484292385471162124464248375625748097868775829652908052615424796255913420292818674303286242639225711610323988077268116737", 10)
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
		})
}
