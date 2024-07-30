package sw_bls12381

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		doublePairingCheckHint,
	}
}

func doublePairingCheckHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	// This is inspired from https://eprint.iacr.org/2024/640.pdf
	// and based on a personal communication with the author Andrija Novakovic.
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var P0, P1 bls12381.G1Affine
			var Q0, Q1 bls12381.G2Affine

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

			lines0 := bls12381.PrecomputeLines(Q0)
			lines1 := bls12381.PrecomputeLines(Q1)
			millerLoop, err := bls12381.MillerLoopFixedQ(
				[]bls12381.G1Affine{P0, P1},
				[][2][len(bls12381.LoopCounter) - 1]bls12381.LineEvaluationAff{lines0, lines1},
			)
			millerLoop.Conjugate(&millerLoop)
			if err != nil {
				return err
			}

			var root, rootPthInverse, root27thInverse, residueWitness, scalingFactor bls12381.E12
			var order3rd, order3rdPower, exponent, exponentInv, finalExpFactor, polyFactor big.Int
			// polyFactor = (1-x)/3
			polyFactor.SetString("5044125407647214251", 10)
			// finalExpFactor = ((q^12 - 1) / r) / (27 * polyFactor)
			finalExpFactor.SetString("2366356426548243601069753987687709088104621721678962410379583120840019275952471579477684846670499039076873213559162845121989217658133790336552276567078487633052653005423051750848782286407340332979263075575489766963251914185767058009683318020965829271737924625612375201545022326908440428522712877494557944965298566001441468676802477524234094954960009227631543471415676620753242466901942121887152806837594306028649150255258504417829961387165043999299071444887652375514277477719817175923289019181393803729926249507024121957184340179467502106891835144220611408665090353102353194448552304429530104218473070114105759487413726485729058069746063140422361472585604626055492939586602274983146215294625774144156395553405525711143696689756441298365274341189385646499074862712688473936093315628166094221735056483459332831845007196600723053356837526749543765815988577005929923802636375670820616189737737304893769679803809426304143627363860243558537831172903494450556755190448279875942974830469855835666815454271389438587399739607656399812689280234103023464545891697941661992848552456326290792224091557256350095392859243101357349751064730561345062266850238821755009430903520645523345000326783803935359711318798844368754833295302563158150573540616830138810935344206231367357992991289265295323280", 10)

			// 1. get pth-root inverse
			exponent.Mul(&finalExpFactor, big.NewInt(27))
			root.Exp(millerLoop, &exponent)
			if root.IsOne() {
				rootPthInverse.SetOne()
			} else {
				exponentInv.ModInverse(&exponent, &polyFactor)
				exponent.Neg(&exponentInv).Mod(&exponent, &polyFactor)
				rootPthInverse.Exp(root, &exponent)
			}

			// 2.1. get order of 3rd primitive root
			var three big.Int
			three.SetUint64(3)
			exponent.Mul(&polyFactor, &finalExpFactor)
			root.Exp(millerLoop, &exponent)
			if root.IsOne() {
				order3rdPower.SetUint64(0)
			}
			root.Exp(root, &three)
			if root.IsOne() {
				order3rdPower.SetUint64(1)
			}
			root.Exp(root, &three)
			if root.IsOne() {
				order3rdPower.SetUint64(2)
			}
			root.Exp(root, &three)
			if root.IsOne() {
				order3rdPower.SetUint64(3)
			}

			// 2.2. get 27th root inverse
			if order3rdPower.Uint64() == 0 {
				root27thInverse.SetOne()
			} else {
				order3rd.Exp(&three, &order3rdPower, nil)
				exponent.Mul(&polyFactor, &finalExpFactor)
				root.Exp(millerLoop, &exponent)
				exponentInv.ModInverse(&exponent, &order3rd)
				exponent.Neg(&exponentInv).Mod(&exponent, &order3rd)
				root27thInverse.Exp(root, &exponent)
			}

			// 2.3. shift the Miller loop result so that millerLoop * scalingFactor
			// is of order finalExpFactor
			scalingFactor.Mul(&rootPthInverse, &root27thInverse)
			millerLoop.Mul(&millerLoop, &scalingFactor)

			// 3. get the witness residue
			//
			// lambda = q - u, the optimal exponent
			var lambda big.Int
			lambda.SetString("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129030796414117214202539", 10)
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
		})
}
