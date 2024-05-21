package eddsa

import (
	"errors"

	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/hash"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"

	edwardsbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	edwardsbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	edwardsbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards"
	edwardsbls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/twistededwards"
	edwardsbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	edwardsbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/twistededwards"
	edwardsbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
)

// PublicKey stores an eddsa public key (to be used in gnark circuit)
type PublicKey struct {
	A twistededwards.Point
}

// Signature stores a signature  (to be used in gnark circuit)
// An EdDSA signature is a tuple (R,S) where R is a point on the twisted Edwards curve
// and S a scalar. Since the base field of the twisted Edwards is Fr, the number of points
// N on the Edwards is < r+1+2sqrt(r)+2 (since the curve has 2 points of multiplicity 2).
// The subgroup l used in eddsa is <1/2N, so the reduction
// mod l ensures S < r, therefore there is no risk of overflow.
type Signature struct {
	R twistededwards.Point
	S frontend.Variable
}

// Verify verifies an eddsa signature using MiMC hash function
// cf https://en.wikipedia.org/wiki/EdDSA
func Verify(curve twistededwards.Curve, sig Signature, msg frontend.Variable, pubKey PublicKey, hash hash.FieldHasher) error {

	// compute H(R, A, M)
	hash.Write(sig.R.X)
	hash.Write(sig.R.Y)
	hash.Write(pubKey.A.X)
	hash.Write(pubKey.A.Y)
	hash.Write(msg)
	hRAM := hash.Sum()

	base := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}

	//[S]G-[H(R,A,M)]*A
	_A := curve.Neg(pubKey.A)
	Q := curve.DoubleBaseScalarMul(base, _A, sig.S, hRAM)
	curve.AssertIsOnCurve(Q)

	//[S]G-[H(R,A,M)]*A-R
	Q = curve.Add(curve.Neg(Q), sig.R)

	// [cofactor]*(lhs-rhs)
	log := logger.Logger()
	if !curve.Params().Cofactor.IsUint64() {
		err := errors.New("invalid cofactor")
		log.Err(err).Str("cofactor", curve.Params().Cofactor.String()).Send()
		return err
	}
	cofactor := curve.Params().Cofactor.Uint64()
	switch cofactor {
	case 4:
		Q = curve.Double(curve.Double(Q))
	case 8:
		Q = curve.Double(curve.Double(curve.Double(Q)))
	default:
		log.Warn().Str("cofactor", curve.Params().Cofactor.String()).Msg("curve cofactor is not implemented")
	}

	curve.API().AssertIsEqual(Q.X, 0)
	curve.API().AssertIsEqual(Q.Y, 1)

	return nil
}

// Assign is a helper to assigned a compressed binary public key representation into its uncompressed form
func (p *PublicKey) Assign(curveID tedwards.ID, buf []byte) {
	ax, ay, err := parsePoint(curveID, buf)
	if err != nil {
		panic(err)
	}
	p.A.X = ax
	p.A.Y = ay
}

// Assign is a helper to assigned a compressed binary signature representation into its uncompressed form
func (s *Signature) Assign(curveID tedwards.ID, buf []byte) {
	rx, ry, S, err := parseSignature(curveID, buf)
	if err != nil {
		panic(err)
	}
	s.R.X = rx
	s.R.Y = ry
	s.S = S
}

// parseSignature parses a compressed binary signature into uncompressed R.X, R.Y and S
func parseSignature(curveID tedwards.ID, buf []byte) ([]byte, []byte, []byte, error) {

	var pointbn254 edwardsbn254.PointAffine
	var pointbls12381 edwardsbls12381.PointAffine
	var pointbls12377 edwardsbls12377.PointAffine
	var pointbw6761 edwardsbw6761.PointAffine
	var pointbls24315 edwardsbls24315.PointAffine
	var pointbls24317 edwardsbls24317.PointAffine
	var pointbw6633 edwardsbw6633.PointAffine

	switch curveID {
	case tedwards.BN254:
		if _, err := pointbn254.SetBytes(buf[:32]); err != nil {
			return nil, nil, nil, err
		}
		a, b, err := parsePoint(curveID, buf)
		if err != nil {
			return nil, nil, nil, err
		}
		s := buf[32:]
		return a, b, s, nil
	case tedwards.BLS12_381:
		if _, err := pointbls12381.SetBytes(buf[:32]); err != nil {
			return nil, nil, nil, err
		}
		a, b, err := parsePoint(curveID, buf)
		if err != nil {
			return nil, nil, nil, err
		}
		s := buf[32:]
		return a, b, s, nil
	case tedwards.BLS12_377:
		if _, err := pointbls12377.SetBytes(buf[:32]); err != nil {
			return nil, nil, nil, err
		}
		a, b, err := parsePoint(curveID, buf)
		if err != nil {
			return nil, nil, nil, err
		}
		s := buf[32:]
		return a, b, s, nil
	case tedwards.BW6_761:
		if _, err := pointbw6761.SetBytes(buf[:48]); err != nil {
			return nil, nil, nil, err
		}
		a, b, err := parsePoint(curveID, buf)
		if err != nil {
			return nil, nil, nil, err
		}
		s := buf[48:]
		return a, b, s, nil
	case tedwards.BLS24_317:
		if _, err := pointbls24317.SetBytes(buf[:32]); err != nil {
			return nil, nil, nil, err
		}
		a, b, err := parsePoint(curveID, buf)
		if err != nil {
			return nil, nil, nil, err
		}
		s := buf[32:]
		return a, b, s, nil
	case tedwards.BLS24_315:
		if _, err := pointbls24315.SetBytes(buf[:32]); err != nil {
			return nil, nil, nil, err
		}
		a, b, err := parsePoint(curveID, buf)
		if err != nil {
			return nil, nil, nil, err
		}
		s := buf[32:]
		return a, b, s, nil
	case tedwards.BW6_633:
		if _, err := pointbw6633.SetBytes(buf[:40]); err != nil {
			return nil, nil, nil, err
		}
		a, b, err := parsePoint(curveID, buf)
		if err != nil {
			return nil, nil, nil, err
		}
		s := buf[40:]
		return a, b, s, nil
	default:
		panic("not implemented")
	}
}

// parsePoint parses a compressed binary point into uncompressed P.X and P.Y
func parsePoint(curveID tedwards.ID, buf []byte) ([]byte, []byte, error) {
	var pointbn254 edwardsbn254.PointAffine
	var pointbls12381 edwardsbls12381.PointAffine
	var pointbls12377 edwardsbls12377.PointAffine
	var pointbw6761 edwardsbw6761.PointAffine
	var pointbls24315 edwardsbls24315.PointAffine
	var pointbls24317 edwardsbls24317.PointAffine
	var pointbw6633 edwardsbw6633.PointAffine
	switch curveID {
	case tedwards.BN254:
		if _, err := pointbn254.SetBytes(buf[:32]); err != nil {
			return nil, nil, err
		}
		a := pointbn254.X.Bytes()
		b := pointbn254.Y.Bytes()
		return a[:], b[:], nil
	case tedwards.BLS12_381:
		if _, err := pointbls12381.SetBytes(buf[:32]); err != nil {
			return nil, nil, err
		}
		a := pointbls12381.X.Bytes()
		b := pointbls12381.Y.Bytes()
		return a[:], b[:], nil
	case tedwards.BLS12_377:
		if _, err := pointbls12377.SetBytes(buf[:32]); err != nil {
			return nil, nil, err
		}
		a := pointbls12377.X.Bytes()
		b := pointbls12377.Y.Bytes()
		return a[:], b[:], nil
	case tedwards.BW6_761:
		if _, err := pointbw6761.SetBytes(buf[:48]); err != nil {
			return nil, nil, err
		}
		a := pointbw6761.X.Bytes()
		b := pointbw6761.Y.Bytes()
		return a[:], b[:], nil
	case tedwards.BLS24_317:
		if _, err := pointbls24317.SetBytes(buf[:32]); err != nil {
			return nil, nil, err
		}
		a := pointbls24317.X.Bytes()
		b := pointbls24317.Y.Bytes()
		return a[:], b[:], nil
	case tedwards.BLS24_315:
		if _, err := pointbls24315.SetBytes(buf[:32]); err != nil {
			return nil, nil, err
		}
		a := pointbls24315.X.Bytes()
		b := pointbls24315.Y.Bytes()
		return a[:], b[:], nil
	case tedwards.BW6_633:
		if _, err := pointbw6633.SetBytes(buf[:40]); err != nil {
			return nil, nil, err
		}
		a := pointbw6633.X.Bytes()
		b := pointbw6633.Y.Bytes()
		return a[:], b[:], nil
	default:
		panic("not implemented")
	}
}
