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
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	cryptofs "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"
	"github.com/consensys/gnark/std/math/emulated"
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
		ecc.BLS12_377,
		ecc.BW6_761,
	}
	innerCurves := []ecc.ID{
		ecc.BN254,
		ecc.BLS12_377,
		ecc.BW6_761,
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
				assert.CheckCircuit(circuit, test.WithCurves(outer), test.WithValidAssignment(witness), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks(), test.NoProverChecks())
			}, outer.String(), inner.String())
		}
	}
}

type hashMarshalG1Circuit[FR emulated.FieldParams, G1El algebra.G1ElementT] struct {
	Point    G1El
	Expected frontend.Variable
}

func (c *hashMarshalG1Circuit[FR, G1El]) Define(api frontend.API) error {
	var fr FR
	h, err := recursion.NewHash(api, fr.Modulus(), true)
	if err != nil {
		return fmt.Errorf("new hash: %w", err)
	}
	curve, err := algebra.GetCurve[FR, G1El](api)
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
		var g bw6761.G1Affine
		var s fr_bw6761.Element
		s.SetRandom()
		g.ScalarMultiplicationBase(s.BigInt(new(big.Int)))
		h, err := recursion.NewShort(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())
		assert.NoError(err)
		marshalled := g.Marshal()
		h.Write(marshalled)
		hashed := h.Sum(nil)
		circuit := &hashMarshalG1Circuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine]{}
		assignment := &hashMarshalG1Circuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine]{
			Point:    sw_bw6761.NewG1Affine(g),
			Expected: hashed,
		}
		assert.CheckCircuit(circuit, test.WithCurves(ecc.BN254), test.WithValidAssignment(assignment), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks(), test.NoProverChecks())
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
		circuit := &hashMarshalG1Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine]{}
		assignment := &hashMarshalG1Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine]{
			Point:    sw_bls12377.NewG1Affine(g),
			Expected: hashed,
		}
		assert.CheckCircuit(circuit, test.WithCurves(ecc.BW6_761), test.WithValidAssignment(assignment), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks(), test.NoProverChecks())
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
		circuit := &hashMarshalG1Circuit[sw_bls24315.ScalarField, sw_bls24315.G1Affine]{}
		assignment := &hashMarshalG1Circuit[sw_bls24315.ScalarField, sw_bls24315.G1Affine]{
			Point:    sw_bls24315.NewG1Affine(g),
			Expected: hashed,
		}
		assert.CheckCircuit(circuit, test.WithCurves(ecc.BW6_633), test.WithValidAssignment(assignment), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks(), test.NoProverChecks())
	})
}

type hashMarshalScalarCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT] struct {
	Scalar   emulated.Element[FR]
	Expected frontend.Variable
}

func (c *hashMarshalScalarCircuit[FR, G1El]) Define(api frontend.API) error {
	var fr FR
	h, err := recursion.NewHash(api, fr.Modulus(), true)
	if err != nil {
		return fmt.Errorf("new hash: %w", err)
	}
	curve, err := algebra.GetCurve[FR, G1El](api)
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
		var s fr_bw6761.Element
		s.SetRandom()
		h, err := recursion.NewShort(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())
		assert.NoError(err)
		marshalled := s.Marshal()
		h.Write(marshalled)
		hashed := h.Sum(nil)
		circuit := &hashMarshalScalarCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine]{}
		assignment := &hashMarshalScalarCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine]{
			Scalar:   sw_bw6761.NewScalar(s),
			Expected: hashed,
		}
		assert.CheckCircuit(circuit, test.WithCurves(ecc.BN254), test.WithValidAssignment(assignment), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks(), test.NoProverChecks())
	})
	assert.Run(func(assert *test.Assert) {
		var s fr_bls12377.Element
		s.SetRandom()
		h, err := recursion.NewShort(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
		assert.NoError(err)
		marshalled := s.Marshal()
		h.Write(marshalled)
		hashed := h.Sum(nil)
		circuit := &hashMarshalScalarCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine]{}
		assignment := &hashMarshalScalarCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine]{
			Scalar:   sw_bls12377.NewScalar(s),
			Expected: hashed,
		}
		assert.CheckCircuit(circuit, test.WithCurves(ecc.BW6_761), test.WithValidAssignment(assignment), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks(), test.NoProverChecks())
	})
	assert.Run(func(assert *test.Assert) {
		var s fr_bls24315.Element
		s.SetRandom()
		h, err := recursion.NewShort(ecc.BW6_633.ScalarField(), ecc.BLS24_315.ScalarField())
		assert.NoError(err)
		marshalled := s.Marshal()
		h.Write(marshalled)
		hashed := h.Sum(nil)
		circuit := &hashMarshalScalarCircuit[sw_bls24315.ScalarField, sw_bls24315.G1Affine]{}
		assignment := &hashMarshalScalarCircuit[sw_bls24315.ScalarField, sw_bls24315.G1Affine]{
			Scalar:   sw_bls24315.NewScalar(s),
			Expected: hashed,
		}
		assert.CheckCircuit(circuit, test.WithCurves(ecc.BW6_633), test.WithValidAssignment(assignment), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks(), test.NoProverChecks())
	})
}

type transcriptCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT] struct {
	Challenges [3]string
	Points     [3][3]G1El
	Expected   [3]frontend.Variable
}

func (c *transcriptCircuit[FR, G1El]) Define(api frontend.API) error {
	var fr FR
	fs, err := recursion.NewTranscript(api, fr.Modulus(), c.Challenges[:])
	if err != nil {
		return fmt.Errorf("new transcript: %w", err)
	}
	curve, err := algebra.GetCurve[FR, G1El](api)
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

func TestTranscriptMarshal(t *testing.T) {
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
		circuit := &transcriptCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine]{
			Challenges: challenges,
		}
		assignment := &transcriptCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine]{
			Challenges: challenges,
			Points:     points,
			Expected:   expected,
		}
		assert.CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithCurves(ecc.BW6_761), test.NoFuzzing(), test.NoSerializationChecks(), test.NoProverChecks())
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
		circuit := &transcriptCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine]{
			Challenges: challenges,
		}
		assignment := &transcriptCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine]{
			Challenges: challenges,
			Points:     points,
			Expected:   expected,
		}
		assert.CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithCurves(ecc.BN254), test.NoFuzzing(), test.NoSerializationChecks(), test.NoProverChecks())
	}, "bn254")
}
