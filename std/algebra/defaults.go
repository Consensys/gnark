package algebra

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

func GetCurve[S ScalarT, G1El G1ElementT](api frontend.API) (Curve[S, G1El], error) {
	var ret Curve[S, G1El]
	switch s := any(&ret).(type) {
	case *Curve[sw_bn254.Scalar, sw_bn254.G1Affine]:
		c, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetBN254Params())
		if err != nil {
			return ret, fmt.Errorf("new curve: %w", err)
		}
		*s = c
	case *Curve[sw_bls12377.Scalar, sw_bls12377.G1Affine]:
		c := sw_bls12377.NewCurve(api)
		*s = c
	default:
		return ret, fmt.Errorf("unknown type parametrisation")
	}
	return ret, nil
}

func GetPairing[G1El G1ElementT, G2El G2ElementT, GtEl GtElementT](api frontend.API) (Pairing[G1El, G2El, GtEl], error) {
	var ret Pairing[G1El, G2El, GtEl]
	switch s := any(&ret).(type) {
	case *Pairing[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]:
		p, err := sw_bn254.NewPairing(api)
		if err != nil {
			return ret, fmt.Errorf("new pairing: %w", err)
		}
		*s = p
	case *Pairing[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]:
		p := sw_bls12377.NewPairing(api)
		*s = p
	default:
		return ret, fmt.Errorf("unknown type parametrisation")
	}
	return ret, nil
}
