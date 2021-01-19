package witness

import (
	"io"

	witness_bls377 "github.com/consensys/gnark/internal/backend/bls377/witness"
	witness_bls381 "github.com/consensys/gnark/internal/backend/bls381/witness"
	witness_bn256 "github.com/consensys/gnark/internal/backend/bn256/witness"
	witness_bw761 "github.com/consensys/gnark/internal/backend/bw761/witness"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

// WriteFull serialize full witness [secret|one_wire|public] by encoding provided values into
// fr.Element of provided curveID
func WriteFull(w io.Writer, witness frontend.Witness, curveID gurvy.ID) error {
	switch curveID {
	case gurvy.BN256:
		return witness_bn256.WriteFull(w, witness)
	case gurvy.BLS377:
		return witness_bls377.WriteFull(w, witness)
	case gurvy.BLS381:
		return witness_bls381.WriteFull(w, witness)
	case gurvy.BW761:
		return witness_bw761.WriteFull(w, witness)
	default:
		panic("unimplemented curve type")
	}
}

// WritePublic serialize public witness [public], without the one_wire, by encoding provided values into
// fr.Element of provided curveID
func WritePublic(w io.Writer, publicWitness frontend.Witness, curveID gurvy.ID) error {
	switch curveID {
	case gurvy.BN256:
		return witness_bn256.WritePublic(w, publicWitness)
	case gurvy.BLS377:
		return witness_bls377.WritePublic(w, publicWitness)
	case gurvy.BLS381:
		return witness_bls381.WritePublic(w, publicWitness)
	case gurvy.BW761:
		return witness_bw761.WritePublic(w, publicWitness)
	default:
		panic("unimplemented curve type")
	}
}
