package poseidon2

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/field/koalabear"
	kbposeidon2 "github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
)

// diag16KoalaBearMinus1 holds the entries the in-circuit matMulInternalInPlace
// multiplies by per coordinate (state[i] = state[i] * DiagM1[i] + Σstate).
// For koalabear they match the unexported diag16 array in gnark-crypto
// (field/koalabear/poseidon2/hash.go:48-69) directly; the "M1" naming is a
// gnark convention shared with bn254 and is unrelated to a "-1" shift.
//
// p = 2^31 - 2^24 + 1 = 2_130_706_433.
var diag16KoalaBearMinus1 = [16]uint64{
	2130706431, // -2  mod p
	1,          //  1
	2,          //  2
	1065353217, //  1/2  mod p
	3,          //  3
	4,          //  4
	1065353216, // -1/2  mod p
	2130706430, // -3   mod p
	2130706429, // -4   mod p
	2122383361, //  1/2^8 mod p
	1864368129, //  1/8   mod p
	2130706306, //  1/2^24 mod p
	8323072,    // -1/2^8 mod p
	266338304,  // -1/8   mod p
	133169152,  // -1/16  mod p
	127,        // -1/2^24 mod p
}

// isKoalaBearField reports whether the api compiles over the koalabear native
// field.
func isKoalaBearField(field *big.Int) bool {
	return field.Cmp(koalabear.Modulus()) == 0
}

// koalaBearParameters builds in-circuit Parameters from gnark-crypto's native
// koalabear poseidon2 parameters. Round keys come from the same deterministic
// seed-based derivation used natively, so circuit and native permutations
// produce identical outputs for the same input.
func koalaBearParameters(width, nbFullRounds, nbPartialRounds int) (Parameters, error) {
	native := kbposeidon2.NewParameters(width, nbFullRounds, nbPartialRounds)
	params := Parameters{
		Width:           native.Width,
		DegreeSBox:      kbposeidon2.DegreeSBox(),
		NbFullRounds:    native.NbFullRounds,
		NbPartialRounds: native.NbPartialRounds,
		RoundKeys:       make([][]big.Int, len(native.RoundKeys)),
	}
	for i := range params.RoundKeys {
		params.RoundKeys[i] = make([]big.Int, len(native.RoundKeys[i]))
		for j := range params.RoundKeys[i] {
			native.RoundKeys[i][j].BigInt(&params.RoundKeys[i][j])
		}
	}

	if width != 16 {
		return Parameters{}, fmt.Errorf("koalabear poseidon2: in-circuit width %d not yet supported (only 16)", width)
	}
	params.DiagM1 = make([]big.Int, 16)
	for i, v := range diag16KoalaBearMinus1 {
		params.DiagM1[i].SetUint64(v)
	}
	params.useKoalaBearM4 = true
	return params, nil
}
