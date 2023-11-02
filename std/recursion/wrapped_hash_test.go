package recursion_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	cryptofs "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/test"
)

type shortHashCircuit struct {
	Input  []frontend.Variable
	Output frontend.Variable
	inner  ecc.ID
}

func (c *shortHashCircuit) Define(api frontend.API) error {
	hasher, err := recursion.NewHash(api, c.inner.ScalarField(), false)
	if err != nil {
		return err
	}
	for i := range c.Input {
		hasher.Write(c.Input[i])
	}
	res := hasher.Sum()
	api.AssertIsEqual(c.Output, res)
	return nil
}

func TestShortHash(t *testing.T) {
	outerCurves := []ecc.ID{
		ecc.BN254,
		ecc.BLS12_381,
		ecc.BLS12_377,
		ecc.BW6_761,
		ecc.BW6_633,
		ecc.BLS24_315,
		ecc.BLS24_317,
	}
	innerCurves := []ecc.ID{
		ecc.BN254,
		ecc.BLS12_381,
		ecc.BLS12_377,
		ecc.BW6_761,
		ecc.BW6_633,
		ecc.BLS24_315,
		ecc.BLS24_317,
	}

	assert := test.NewAssert(t)
	nbInputs := 19
	for _, outer := range outerCurves {
		outer := outer
		for _, inner := range innerCurves {
			inner := inner
			assert.Run(func(assert *test.Assert) {
				circuit := &shortHashCircuit{Input: make([]frontend.Variable, nbInputs), inner: inner}
				h, err := recursion.NewShort(outer.ScalarField(), inner.ScalarField())
				assert.NoError(err)
				witness := &shortHashCircuit{Input: make([]frontend.Variable, nbInputs), inner: inner}
				buf := make([]byte, (outer.ScalarField().BitLen()+7)/8)
				for i := range witness.Input {
					el, err := rand.Int(rand.Reader, outer.ScalarField())
					assert.NoError(err)
					el.FillBytes(buf)
					h.Write(buf)
					witness.Input[i] = el
				}
				res := h.Sum(nil)
				witness.Output = res
				assert.CheckCircuit(circuit, test.WithCurves(outer), test.WithValidAssignment(witness), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks())
			}, outer.String(), inner.String())
		}
	}
}

type hashMarshalG1Circuit[S algebra.ScalarT, G1El algebra.G1ElementT] struct {
	Point    G1El
	Expected frontend.Variable

	target *big.Int
}

func (c *hashMarshalG1Circuit[S, G1El]) Define(api frontend.API) error {
	h, err := recursion.NewHash(api, c.target, true)
	if err != nil {
		return fmt.Errorf("new hash: %w", err)
	}
	curve, err := algebra.GetCurve[S, G1El](api)
	if err != nil {
		return fmt.Errorf("get curve: %w", err)
	}
	marshlled := curve.MarshalG1(c.Point)
	h.Write(marshlled...)
	res := h.Sum()
	api.AssertIsEqual(res, c.Expected)
	return nil
}

func TestHashMarshalG1(t *testing.T) {
	assert := test.NewAssert(t)

	assert.Run(func(assert *test.Assert) {
		var g bn254.G1Affine
		var s fr_bn254.Element
		s.SetRandom()
		g.ScalarMultiplicationBase(s.BigInt(new(big.Int)))
		h, err := recursion.NewShort(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())
		assert.NoError(err)
		marshalled := g.Marshal()
		h.Write(marshalled)
		hashed := h.Sum(nil)
		circuit := &hashMarshalG1Circuit[sw_bn254.Scalar, sw_bn254.G1Affine]{
			target: ecc.BW6_761.ScalarField(),
		}
		assignment := &hashMarshalG1Circuit[sw_bn254.Scalar, sw_bn254.G1Affine]{
			Point:    sw_bn254.NewG1Affine(g),
			Expected: hashed,
			target:   ecc.BW6_761.ScalarField(),
		}
		assert.CheckCircuit(circuit, test.WithCurves(ecc.BN254), test.WithValidAssignment(assignment), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks())
	})
	assert.Run(func(assert *test.Assert) {
		var g bls12377.G1Affine
		var s fr_bls12377.Element
		s.SetRandom()
		g.ScalarMultiplicationBase(s.BigInt(new(big.Int)))
		h, err := recursion.NewShort(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
		assert.NoError(err)
		marshalled := g.Marshal()
		h.Write(marshalled)
		hashed := h.Sum(nil)
		circuit := &hashMarshalG1Circuit[sw_bls12377.Scalar, sw_bls12377.G1Affine]{
			target: ecc.BLS12_377.ScalarField(),
		}
		assignment := &hashMarshalG1Circuit[sw_bls12377.Scalar, sw_bls12377.G1Affine]{
			Point:    sw_bls12377.NewG1Affine(g),
			Expected: hashed,
			target:   ecc.BLS12_377.ScalarField(),
		}
		assert.CheckCircuit(circuit, test.WithCurves(ecc.BW6_761), test.WithValidAssignment(assignment), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks())
	})
	assert.Run(func(assert *test.Assert) {
		var g bls24315.G1Affine
		var s fr_bls24315.Element
		s.SetRandom()
		g.ScalarMultiplicationBase(s.BigInt(new(big.Int)))
		h, err := recursion.NewShort(ecc.BW6_633.ScalarField(), ecc.BLS24_315.ScalarField())
		assert.NoError(err)
		marshalled := g.Marshal()
		h.Write(marshalled)
		hashed := h.Sum(nil)
		circuit := &hashMarshalG1Circuit[sw_bls24315.Scalar, sw_bls24315.G1Affine]{
			target: ecc.BLS12_377.ScalarField(),
		}
		assignment := &hashMarshalG1Circuit[sw_bls24315.Scalar, sw_bls24315.G1Affine]{
			Point:    sw_bls24315.NewG1Affine(g),
			Expected: hashed,
			target:   ecc.BLS12_377.ScalarField(),
		}
		assert.CheckCircuit(circuit, test.WithCurves(ecc.BW6_633), test.WithValidAssignment(assignment), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks())
	})
}

type hashMarshalScalarCircuit[S algebra.ScalarT, G1El algebra.G1ElementT] struct {
	Scalar   S
	Expected frontend.Variable

	target *big.Int
}

func (c *hashMarshalScalarCircuit[S, G1El]) Define(api frontend.API) error {
	h, err := recursion.NewHash(api, c.target, true)
	if err != nil {
		return fmt.Errorf("new hash: %w", err)
	}
	curve, err := algebra.GetCurve[S, G1El](api)
	if err != nil {
		return fmt.Errorf("get curve: %w", err)
	}
	marshlled := curve.MarshalScalar(c.Scalar)
	h.Write(marshlled...)
	res := h.Sum()
	api.AssertIsEqual(res, c.Expected)
	return nil
}

func TestHashMarshalScalar(t *testing.T) {
	assert := test.NewAssert(t)

	assert.Run(func(assert *test.Assert) {
		var s fr_bn254.Element
		s.SetRandom()
		h, err := recursion.NewShort(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())
		assert.NoError(err)
		marshalled := s.Marshal()
		h.Write(marshalled)
		hashed := h.Sum(nil)
		circuit := &hashMarshalScalarCircuit[sw_bn254.Scalar, sw_bn254.G1Affine]{
			target: ecc.BW6_761.ScalarField(),
		}
		assignment := &hashMarshalScalarCircuit[sw_bn254.Scalar, sw_bn254.G1Affine]{
			Scalar:   sw_bn254.NewScalar(s),
			Expected: hashed,
			target:   ecc.BW6_761.ScalarField(),
		}
		assert.CheckCircuit(circuit, test.WithCurves(ecc.BN254), test.WithValidAssignment(assignment), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks())
	})
	assert.Run(func(assert *test.Assert) {
		var s fr_bls12377.Element
		s.SetRandom()
		h, err := recursion.NewShort(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
		assert.NoError(err)
		marshalled := s.Marshal()
		h.Write(marshalled)
		hashed := h.Sum(nil)
		circuit := &hashMarshalScalarCircuit[sw_bls12377.Scalar, sw_bls12377.G1Affine]{
			target: ecc.BLS12_377.ScalarField(),
		}
		assignment := &hashMarshalScalarCircuit[sw_bls12377.Scalar, sw_bls12377.G1Affine]{
			Scalar:   s.String(),
			Expected: hashed,
			target:   ecc.BLS12_377.ScalarField(),
		}
		assert.CheckCircuit(circuit, test.WithCurves(ecc.BW6_761), test.WithValidAssignment(assignment), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks())
	})
	assert.Run(func(assert *test.Assert) {
		var s fr_bls24315.Element
		s.SetRandom()
		h, err := recursion.NewShort(ecc.BW6_633.ScalarField(), ecc.BLS24_315.ScalarField())
		assert.NoError(err)
		marshalled := s.Marshal()
		h.Write(marshalled)
		hashed := h.Sum(nil)
		circuit := &hashMarshalScalarCircuit[sw_bls24315.Scalar, sw_bls24315.G1Affine]{
			target: ecc.BLS12_377.ScalarField(),
		}
		assignment := &hashMarshalScalarCircuit[sw_bls24315.Scalar, sw_bls24315.G1Affine]{
			Scalar:   s.String(),
			Expected: hashed,
			target:   ecc.BLS12_377.ScalarField(),
		}
		assert.CheckCircuit(circuit, test.WithCurves(ecc.BW6_633), test.WithValidAssignment(assignment), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks())
	})
}

type transcriptCircuit[S algebra.ScalarT, G1El algebra.G1ElementT] struct {
	Challenges [3]string
	Points     [3][3]G1El
	Expected   [3]frontend.Variable

	target *big.Int
}

func (c *transcriptCircuit[S, G1El]) Define(api frontend.API) error {
	fs, err := recursion.NewTranscript(api, c.target, c.Challenges[:])
	if err != nil {
		return fmt.Errorf("new transcript: %w", err)
	}
	curve, err := algebra.GetCurve[S, G1El](api)
	if err != nil {
		return fmt.Errorf("get curve: %w", err)
	}
	for i := range c.Points {
		for j := range c.Points[i] {
			if err := fs.Bind(c.Challenges[i], curve.MarshalG1(c.Points[i][j])); err != nil {
				return fmt.Errorf("bind[%d][%d] %w", i, j, err)
			}
		}
	}
	for i := range c.Expected {
		res, err := fs.ComputeChallenge(c.Challenges[i])
		if err != nil {
			return fmt.Errorf("compute challenge %d: %w", i, err)
		}
		api.AssertIsEqual(res, c.Expected[i])
	}
	return nil
}

func TestTranscriptMarsha(t *testing.T) {
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		h, err := recursion.NewShort(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
		assert.NoError(err)
		challenges := [3]string{"alfa", "beta", "gamma"}
		fs := cryptofs.NewTranscript(h, challenges[:]...)
		var points [3][3]sw_bls12377.G1Affine
		for i := range points {
			for j := range points[i] {
				var p bls12377.G1Affine
				r, err := rand.Int(rand.Reader, ecc.BLS12_377.ScalarField())
				assert.NoError(err)
				p.ScalarMultiplicationBase(r)
				points[i][j] = sw_bls12377.NewG1Affine(p)
				if err := fs.Bind(challenges[i], p.Marshal()); err != nil {
					t.Fatal("bind", err)
				}
			}
		}
		var expected [3]frontend.Variable
		for i := range expected {
			res, err := fs.ComputeChallenge(challenges[i])
			assert.NoError(err)
			expected[i] = res
		}
		circuit := &transcriptCircuit[sw_bls12377.Scalar, sw_bls12377.G1Affine]{
			Challenges: challenges,
			target:     ecc.BLS12_377.ScalarField(),
		}
		assignment := &transcriptCircuit[sw_bls12377.Scalar, sw_bls12377.G1Affine]{
			Challenges: challenges,
			Points:     points,
			Expected:   expected,
			target:     ecc.BLS12_377.ScalarField(),
		}
		assert.CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithCurves(ecc.BW6_761), test.NoFuzzing(), test.NoSerializationChecks())
	}, "bw6_761")
	assert.Run(func(assert *test.Assert) {
		h, err := recursion.NewShort(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())
		assert.NoError(err)
		challenges := [3]string{"alfa", "beta", "gamma"}
		fs := cryptofs.NewTranscript(h, challenges[:]...)
		var points [3][3]sw_bw6761.G1Affine
		for i := range points {
			for j := range points[i] {
				var p bw6761.G1Affine
				r, err := rand.Int(rand.Reader, ecc.BW6_761.ScalarField())
				assert.NoError(err)
				p.ScalarMultiplicationBase(r)
				points[i][j] = sw_bw6761.NewG1Affine(p)
				if err := fs.Bind(challenges[i], p.Marshal()); err != nil {
					t.Fatal("bind", err)
				}
			}
		}
		var expected [3]frontend.Variable
		for i := range expected {
			res, err := fs.ComputeChallenge(challenges[i])
			assert.NoError(err)
			expected[i] = res
		}
		circuit := &transcriptCircuit[sw_bw6761.Scalar, sw_bw6761.G1Affine]{
			Challenges: challenges,
			target:     ecc.BW6_761.ScalarField(),
		}
		assignment := &transcriptCircuit[sw_bw6761.Scalar, sw_bw6761.G1Affine]{
			Challenges: challenges,
			Points:     points,
			Expected:   expected,
			target:     ecc.BW6_761.ScalarField(),
		}
		assert.CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithCurves(ecc.BN254), test.NoFuzzing(), test.NoSerializationChecks())
	}, "bn254")
}
