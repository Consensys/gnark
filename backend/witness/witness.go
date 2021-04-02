package witness

import (
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	witness_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/witness"
	witness_bls381 "github.com/consensys/gnark/internal/backend/bls12-381/witness"
	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
	witness_bw761 "github.com/consensys/gnark/internal/backend/bw6-761/witness"

	"github.com/consensys/gnark/frontend"
)

// WriteFullTo encodes the witness to a slice of []fr.Element on the provided curve
// and write the []byte result on provided writer
// returns nb bytes written, error
func WriteFullTo(w io.Writer, curveID ecc.ID, witness frontend.Circuit) (int64, error) {
	switch curveID {
	case ecc.BN254:
		_witness := &witness_bn254.Witness{}
		if err := _witness.FromFullAssignment(witness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BLS12_377:
		_witness := &witness_bls12377.Witness{}
		if err := _witness.FromFullAssignment(witness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BLS12_381:
		_witness := &witness_bls381.Witness{}
		if err := _witness.FromFullAssignment(witness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BW6_761:
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
func WritePublicTo(w io.Writer, curveID ecc.ID, publicWitness frontend.Circuit) (int64, error) {
	switch curveID {
	case ecc.BN254:
		_witness := &witness_bn254.Witness{}
		if err := _witness.FromPublicAssignment(publicWitness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BLS12_377:
		_witness := &witness_bls12377.Witness{}
		if err := _witness.FromPublicAssignment(publicWitness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BLS12_381:
		_witness := &witness_bls381.Witness{}
		if err := _witness.FromPublicAssignment(publicWitness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BW6_761:
		_witness := &witness_bw761.Witness{}
		if err := _witness.FromPublicAssignment(publicWitness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	default:
		panic("not implemented")
	}
}
