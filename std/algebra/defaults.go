package algebra

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

// GetCurve returns the [Curve] implementation corresponding to the scalar and
// G1 type parameters. The method allows to have a fully generic implementation
// without taking into consideration the initialization differences of different
// curves.
func GetCurve[FR emulated.FieldParams, G1El G1ElementT](api frontend.API) (Curve[FR, G1El], error) {
	var ret Curve[FR, G1El]
	switch s := any(&ret).(type) {
	case *Curve[sw_bn254.ScalarField, sw_bn254.G1Affine]:
		c, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetBN254Params())
		if err != nil {
			return ret, fmt.Errorf("new curve: %w", err)
		}
		*s = c
	case *Curve[sw_bw6761.ScalarField, sw_bw6761.G1Affine]:
		c, err := sw_emulated.New[emparams.BW6761Fp, emparams.BW6761Fr](api, sw_emulated.GetBW6761Params())
		if err != nil {
			return ret, fmt.Errorf("new curve: %w", err)
		}
		*s = c
	case *Curve[sw_bls12381.ScalarField, sw_bls12381.G1Affine]:
		c, err := sw_emulated.New[emparams.BLS12381Fp, emparams.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
		if err != nil {
			return ret, fmt.Errorf("new curve: %w", err)
		}
		*s = c
	case *Curve[sw_bls12377.ScalarField, sw_bls12377.G1Affine]:
		c, err := sw_bls12377.NewCurve(api)
		if err != nil {
			return ret, fmt.Errorf("new curve: %w", err)
		}
		*s = c
	case *Curve[sw_bls24315.ScalarField, sw_bls24315.G1Affine]:
		c, err := sw_bls24315.NewCurve(api)
		if err != nil {
			return ret, fmt.Errorf("new curve: %w", err)
		}
		*s = c
	case *Curve[emparams.Secp256k1Fr, sw_emulated.AffinePoint[emparams.Secp256k1Fp]]:
		c, err := sw_emulated.New[emparams.Secp256k1Fp, emparams.Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
		if err != nil {
			return ret, fmt.Errorf("new curve: %w", err)
		}
		*s = c
	default:
		return ret, fmt.Errorf("unknown type parametrisation")
	}
	return ret, nil
}

// GetPairing returns the [Pairing] implementation corresponding to the groups
// type parameters. The method allows to have a fully generic implementation
// without taking into consideration the initialization differences.
func GetPairing[G1El G1ElementT, G2El G2ElementT, GtEl GtElementT](api frontend.API) (Pairing[G1El, G2El, GtEl], error) {
	var ret Pairing[G1El, G2El, GtEl]
	switch s := any(&ret).(type) {
	case *Pairing[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]:
		p, err := sw_bn254.NewPairing(api)
		if err != nil {
			return ret, fmt.Errorf("new pairing: %w", err)
		}
		*s = p
	case *Pairing[sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]:
		p, err := sw_bw6761.NewPairing(api)
		if err != nil {
			return ret, fmt.Errorf("new pairing: %w", err)
		}
		*s = p
	case *Pairing[sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]:
		p, err := sw_bls12381.NewPairing(api)
		if err != nil {
			return ret, fmt.Errorf("new pairing: %w", err)
		}
		*s = p
	case *Pairing[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]:
		p := sw_bls12377.NewPairing(api)
		*s = p
	case *Pairing[sw_bls24315.G1Affine, sw_bls24315.G2Affine, sw_bls24315.GT]:
		p := sw_bls24315.NewPairing(api)
		*s = p
	default:
		return ret, fmt.Errorf("unknown type parametrisation")
	}
	return ret, nil
}
