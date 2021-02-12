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

// WriteFullTo encodes the witness to a slice of []fr.Element on the provided curve
// and write the []byte result on provided writer
// returns nb bytes written, error
func WriteFullTo(w io.Writer, curveID gurvy.ID, witness frontend.Circuit) (int64, error) {
	switch curveID {
	case gurvy.BN256:
		_witness := &witness_bn256.Witness{}
		if err := _witness.FromFullAssignment(witness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case gurvy.BLS377:
		_witness := &witness_bls377.Witness{}
		if err := _witness.FromFullAssignment(witness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case gurvy.BLS381:
		_witness := &witness_bls381.Witness{}
		if err := _witness.FromFullAssignment(witness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case gurvy.BW761:
		_witness := &witness_bw761.Witness{}
		if err := _witness.FromFullAssignment(witness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	default:
		panic("not implemented")
	}
}

// WritePublicTo encodes the witness to a slice of []fr.Element on the provided curve
// and write the []byte result on provided writer
// returns nb bytes written, error
func WritePublicTo(w io.Writer, curveID gurvy.ID, publicWitness frontend.Circuit) (int64, error) {
	switch curveID {
	case gurvy.BN256:
		_witness := &witness_bn256.Witness{}
		if err := _witness.FromPublicAssignment(publicWitness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case gurvy.BLS377:
		_witness := &witness_bls377.Witness{}
		if err := _witness.FromPublicAssignment(publicWitness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case gurvy.BLS381:
		_witness := &witness_bls381.Witness{}
		if err := _witness.FromPublicAssignment(publicWitness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case gurvy.BW761:
		_witness := &witness_bw761.Witness{}
		if err := _witness.FromPublicAssignment(publicWitness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	default:
		panic("not implemented")
	}
}
