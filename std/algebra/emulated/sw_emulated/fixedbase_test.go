package sw_emulated

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fr_secp "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type ScalarMulBaseCombTest[T, S emulated.FieldParams] struct {
	Q AffinePoint[T]
	S emulated.Element[S]
	w int
}

func (c *ScalarMulBaseCombTest[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	res := cr.scalarMulBaseComb(&c.S, c.w)
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

// edge scalars: 0, 1, 2, r−2, r−1 and a 2-power, plus random ones. The point
// [0]G is represented as (0,0) following the package convention.
func combTestScalars(r *big.Int, nbRandom int, randFn func() *big.Int) []*big.Int {
	scalars := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		new(big.Int).Sub(r, big.NewInt(1)),
		new(big.Int).Sub(r, big.NewInt(2)),
		new(big.Int).Lsh(big.NewInt(1), 128),
	}
	for i := 0; i < nbRandom; i++ {
		scalars = append(scalars, randFn())
	}
	return scalars
}

func TestScalarMulBaseCombSecp256k1(t *testing.T) {
	assert := test.NewAssert(t)
	_, g := secp256k1.Generators()
	r := fr_secp.Modulus()
	randFn := func() *big.Int {
		var rnd fr_secp.Element
		_, _ = rnd.SetRandom()
		return rnd.BigInt(new(big.Int))
	}
	for _, w := range []int{4, 8} {
		for _, s := range combTestScalars(r, 3, randFn) {
			var S secp256k1.G1Affine
			S.ScalarMultiplication(&g, s)
			circuit := ScalarMulBaseCombTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{w: w}
			witness := ScalarMulBaseCombTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
				Q: AffinePoint[emulated.Secp256k1Fp]{
					X: emulated.ValueOf[emulated.Secp256k1Fp](S.X),
					Y: emulated.ValueOf[emulated.Secp256k1Fp](S.Y),
				},
			}
			err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
			assert.NoError(err, "w=%d s=%s", w, s.String())
		}
	}
}

func TestScalarMulBaseCombBN254(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, g, _ := bn254.Generators()
	r := fr_bn.Modulus()
	randFn := func() *big.Int {
		var rnd fr_bn.Element
		_, _ = rnd.SetRandom()
		return rnd.BigInt(new(big.Int))
	}
	for _, w := range []int{4, 8} {
		for _, s := range combTestScalars(r, 3, randFn) {
			var S bn254.G1Affine
			S.ScalarMultiplication(&g, s)
			circuit := ScalarMulBaseCombTest[emulated.BN254Fp, emulated.BN254Fr]{w: w}
			witness := ScalarMulBaseCombTest[emulated.BN254Fp, emulated.BN254Fr]{
				S: emulated.ValueOf[emulated.BN254Fr](s),
				Q: AffinePoint[emulated.BN254Fp]{
					X: emulated.ValueOf[emulated.BN254Fp](S.X),
					Y: emulated.ValueOf[emulated.BN254Fp](S.Y),
				},
			}
			err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
			assert.NoError(err, "w=%d s=%s", w, s.String())
		}
	}
}

func TestScalarMulBaseCombP256(t *testing.T) {
	assert := test.NewAssert(t)
	// scalar field order of P-256
	r, _ := new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
	randFn := func() *big.Int {
		rnd, _ := new(big.Int).SetString("3d6a4c9e1b5f2a7d8e9c0b1a2f3e4d5c6b7a8901234567890abcdef012345678", 16)
		return rnd.Mod(rnd, r)
	}
	for _, w := range []int{8} {
		for _, s := range combTestScalars(r, 1, randFn) {
			sr := new(big.Int).Mod(s, r)
			// compute the reference with the generic big.Int arithmetic used
			// for table computation (P-256 has no gnark-crypto counterpart
			// with the same API)
			var Sx, Sy *big.Int
			{
				params := GetP256Params()
				var fpp emulated.P256Fp
				prime := fpp.Modulus()
				if sr.Sign() == 0 {
					Sx, Sy = big.NewInt(0), big.NewInt(0)
				} else {
					acc := &combAffine{x: params.Gx, y: params.Gy}
					var err error
					for i := sr.BitLen() - 2; i >= 0; i-- {
						if acc, err = combDouble(acc, params.A, prime); err != nil {
							t.Fatal(err)
						}
						if sr.Bit(i) == 1 {
							if acc, err = combAdd(acc, &combAffine{x: params.Gx, y: params.Gy}, prime); err != nil {
								t.Fatal(err)
							}
						}
					}
					Sx, Sy = acc.x, acc.y
				}
			}
			circuit := ScalarMulBaseCombTest[emulated.P256Fp, emulated.P256Fr]{w: w}
			witness := ScalarMulBaseCombTest[emulated.P256Fp, emulated.P256Fr]{
				S: emulated.ValueOf[emulated.P256Fr](sr),
				Q: AffinePoint[emulated.P256Fp]{
					X: emulated.ValueOf[emulated.P256Fp](Sx),
					Y: emulated.ValueOf[emulated.P256Fp](Sy),
				},
			}
			err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
			assert.NoError(err, "w=%d s=%s", w, sr.String())
		}
	}
}

// TestScalarMulBaseCombConstraints reports the constraint counts of the comb
// fixed-base scalar multiplication against the current ScalarMulBase.
func TestScalarMulBaseCombConstraints(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	assert := test.NewAssert(t)
	for _, w := range []int{4, 6, 8, 10} {
		circuit := ScalarMulBaseCombTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{w: w}
		ccs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Log("w =", w, "compile error:", err)
			continue
		}
		assert.NoError(err)
		t.Log("comb r1cs", "w =", w, "constraints =", ccs.GetNbConstraints())
	}
	baseline := ScalarMulBaseTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	ccs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &baseline)
	assert.NoError(err)
	t.Log("baseline ScalarMulBase r1cs constraints =", ccs.GetNbConstraints())

	// PLONKish counts
	circuit := ScalarMulBaseCombTest[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{w: 8}
	scsCcs, err := frontend.Compile(testCurve.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(err)
	t.Log("comb scs w=8 constraints =", scsCcs.GetNbConstraints())
	scsBase, err := frontend.Compile(testCurve.ScalarField(), scs.NewBuilder, &baseline)
	assert.NoError(err)
	t.Log("baseline ScalarMulBase scs constraints =", scsBase.GetNbConstraints())
}
