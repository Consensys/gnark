package witness

import (
	"io"
	"math/big"
	"reflect"

	"github.com/consensys/gnark/frontend/schema"
	witness_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/witness"
	witness_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/witness"
	witness_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/witness"
	witness_bls24317 "github.com/consensys/gnark/internal/backend/bls24-317/witness"
	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
	witness_bw6633 "github.com/consensys/gnark/internal/backend/bw6-633/witness"
	witness_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/witness"
	"github.com/consensys/gnark/internal/tinyfield"
	witness_tinyfield "github.com/consensys/gnark/internal/tinyfield/witness"
	"github.com/consensys/gnark/internal/utils"
	"github.com/nume-crypto/gnark-crypto/ecc"
)

type Vector interface {
	io.WriterTo
	io.ReaderFrom
	FromAssignment(assignment interface{}, leafType reflect.Type, publicOnly bool) (*schema.Schema, error)
	ToAssignment(assigment interface{}, leafType reflect.Type, publicOnly bool)
	Len() int
	Type() reflect.Type
}

func newVector(field *big.Int) (Vector, error) {
	var w Vector
	curveID := utils.FieldToCurve(field)
	switch curveID {
	case ecc.BN254:
		w = &witness_bn254.Witness{}
	case ecc.BLS12_377:
		w = &witness_bls12377.Witness{}
	case ecc.BLS12_381:
		w = &witness_bls12381.Witness{}
	case ecc.BW6_761:
		w = &witness_bw6761.Witness{}
	case ecc.BLS24_317:
		w = &witness_bls24317.Witness{}
	case ecc.BLS24_315:
		w = &witness_bls24315.Witness{}
	case ecc.BW6_633:
		w = &witness_bw6633.Witness{}
	default:
		if field.Cmp(tinyfield.Modulus()) == 0 {
			w = &witness_tinyfield.Witness{}
		} else {
			return nil, errMissingCurveID
		}
	}
	return w, nil
}

func newFrom(from Vector, n int) (Vector, error) {
	switch wt := from.(type) {
	case *witness_bn254.Witness:
		a := make(witness_bn254.Witness, n)
		copy(a, *wt)
		return &a, nil
	case *witness_bls12377.Witness:
		a := make(witness_bls12377.Witness, n)
		copy(a, *wt)
		return &a, nil
	case *witness_bls12381.Witness:
		a := make(witness_bls12381.Witness, n)
		copy(a, *wt)
		return &a, nil
	case *witness_bw6761.Witness:
		a := make(witness_bw6761.Witness, n)
		copy(a, *wt)
		return &a, nil
	case *witness_bls24317.Witness:
		a := make(witness_bls24317.Witness, n)
		copy(a, *wt)
		return &a, nil
	case *witness_bls24315.Witness:
		a := make(witness_bls24315.Witness, n)
		copy(a, *wt)
		return &a, nil
	case *witness_bw6633.Witness:
		a := make(witness_bw6633.Witness, n)
		copy(a, *wt)
		return &a, nil
	default:
		return nil, errMissingCurveID
	}
}
