package test

import (
	"crypto/rand"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/frontend"

	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	kzg_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/kzg"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	kzg_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/kzg"

	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
)

const srsCachedSize = (1 << 15) + 3

// NewKZGSRS uses ccs nb variables and nb constraints to initialize a kzg srs
// note that this method is here for convenience only: in production, a SRS generated through MPC should be used.
// for sizes < 2^15, returns a pre-computed cached SRS
func NewKZGSRS(ccs frontend.CompiledConstraintSystem) (kzg.SRS, error) {

	nbConstraints := ccs.GetNbConstraints()
	_, _, public := ccs.GetNbVariables()
	sizeSystem := nbConstraints + public
	kzgSize := ecc.NextPowerOfTwo(uint64(sizeSystem)) + 3

	if kzgSize <= srsCachedSize {
		return getCachedSRS(ccs)
	}

	return newKZGSRS(ccs.CurveID(), kzgSize)

}

var srsCache map[ecc.ID]kzg.SRS

func init() {
	srsCache = make(map[ecc.ID]kzg.SRS)
}
func getCachedSRS(ccs frontend.CompiledConstraintSystem) (kzg.SRS, error) {
	if srs, ok := srsCache[ccs.CurveID()]; ok {
		return srs, nil
	}

	srs, err := newKZGSRS(ccs.CurveID(), srsCachedSize)
	if err != nil {
		return nil, err
	}
	srsCache[ccs.CurveID()] = srs
	return srs, nil
}

func newKZGSRS(curve ecc.ID, kzgSize uint64) (kzg.SRS, error) {
	switch curve {
	case ecc.BN254:
		alpha, err := rand.Int(rand.Reader, fr_bn254.Modulus())
		if err != nil {
			return nil, err
		}
		return kzg_bn254.NewSRS(kzgSize, alpha)
	case ecc.BLS12_381:
		alpha, err := rand.Int(rand.Reader, fr_bls12381.Modulus())
		if err != nil {
			return nil, err
		}
		return kzg_bls12381.NewSRS(kzgSize, alpha)
	case ecc.BLS12_377:
		alpha, err := rand.Int(rand.Reader, fr_bls12377.Modulus())
		if err != nil {
			return nil, err
		}
		return kzg_bls12377.NewSRS(kzgSize, alpha)
	case ecc.BW6_761:
		alpha, err := rand.Int(rand.Reader, fr_bw6761.Modulus())
		if err != nil {
			return nil, err
		}
		return kzg_bw6761.NewSRS(kzgSize, alpha)
	case ecc.BLS24_315:
		alpha, err := rand.Int(rand.Reader, fr_bls24315.Modulus())
		if err != nil {
			return nil, err
		}
		return kzg_bls24315.NewSRS(kzgSize, alpha)
	default:
		panic("unrecognized R1CS curve type")
	}
}
