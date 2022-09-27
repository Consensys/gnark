package witness

import (
	"github.com/consensys/gnark-crypto/ecc"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
	bn254_witness "github.com/consensys/gnark/internal/backend/bn254/witness"
)

/*
	slice c
*/
func WitnessFromFieldSlice(slice []bn254_fr.Element) witness.Witness {
	wt := bn254_witness.Witness(slice)
	return witness.Witness{
		Vector:  &wt,
		CurveID: ecc.BN254,
	}
}
