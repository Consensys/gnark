package evmprecompiles

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// 11: G1 Add
type ecaddG1BLSCircuit struct {
	X0       sw_emulated.AffinePoint[emulated.BLS12381Fp]
	X1       sw_emulated.AffinePoint[emulated.BLS12381Fp]
	Expected sw_emulated.AffinePoint[emulated.BLS12381Fp]
}

func (c *ecaddG1BLSCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return err
	}
	res := ECAddG1BLS(api, &c.X0, &c.X1)
	curve.AssertIsEqual(res, &c.Expected)
	return nil
}

func testRoutineECAddG1BLS() (circ, wit frontend.Circuit) {
	_, _, G, _ := bls12381.Generators()
	var u, v fr.Element
	u.SetRandom()
	v.SetRandom()
	var P, Q bls12381.G1Affine
	P.ScalarMultiplication(&G, u.BigInt(new(big.Int)))
	Q.ScalarMultiplication(&G, v.BigInt(new(big.Int)))
	var expected bls12381.G1Affine
	expected.Add(&P, &Q)
	circuit := ecaddG1BLSCircuit{}
	witness := ecaddG1BLSCircuit{
		X0: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](P.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](P.Y),
		},
		X1: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](Q.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](Q.Y),
		},
		Expected: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](expected.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](expected.Y),
		},
	}
	return &circuit, &witness
}

func TestECAddG1BLSCircuitShort(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECAddG1BLS()
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECAddG1BLSCircuitFull(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECAdd()
	assert.CheckCircuit(circuit, test.WithValidAssignment(witness))
}

// 12: G1 MSM
type ecmsmg1BLSCircuit struct {
	Points  [10]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	Scalars [10]emulated.Element[emulated.BLS12381Fr]
	Res     sw_emulated.AffinePoint[emulated.BLS12381Fp]
	n       int
}

func (c *ecmsmg1BLSCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return err
	}
	ps := make([]*sw_emulated.AffinePoint[emulated.BLS12381Fp], c.n)
	for i := range c.n {
		ps[i] = &c.Points[i]
	}
	ss := make([]*emulated.Element[emulated.BLS12381Fr], c.n)
	for i := range c.n {
		ss[i] = &c.Scalars[i]
	}
	res := ECMSMG1BLS(api, ps, ss)
	curve.AssertIsEqual(res, &c.Res)
	return nil
}

func TestECMSMG1BLSCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	P := make([]bls12381.G1Affine, 10)
	S := make([]fr.Element, 10)
	for i := 0; i < 10; i++ {
		S[i].SetRandom()
		P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	}

	var cP [10]sw_emulated.AffinePoint[emulated.BLS12381Fp]
	for i := range cP {
		cP[i] = sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](P[i].X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](P[i].Y),
		}
	}
	var cS [10]emulated.Element[emulated.BLS12381Fr]
	for i := range cS {
		cS[i] = emulated.ValueOf[emulated.BLS12381Fr](S[i])
	}

	for i := 1; i < 11; i++ {
		var res bls12381.G1Affine
		_, err := res.MultiExp(P[:i], S[:i], ecc.MultiExpConfig{})
		assert.NoError(err)
		err = test.IsSolved(&ecmsmg1BLSCircuit{n: i}, &ecmsmg1BLSCircuit{
			n:       i,
			Points:  cP,
			Scalars: cS,
			Res: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
				X: emulated.ValueOf[emulated.BLS12381Fp](res.X),
				Y: emulated.ValueOf[emulated.BLS12381Fp](res.Y),
			},
		}, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}

// 13: G2 Add
type ecaddG2BLSCircuit struct {
	X0       sw_bls12381.G2Affine
	X1       sw_bls12381.G2Affine
	Expected sw_bls12381.G2Affine
}

func (c *ecaddG2BLSCircuit) Define(api frontend.API) error {
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		panic(err)
	}
	res := ECAddG2BLS(api, &c.X0, &c.X1)
	g2.AssertIsEqual(res, &c.Expected)
	return nil
}

func testRoutineECAddG2BLS() (circ, wit frontend.Circuit) {
	_, _, _, G := bls12381.Generators()
	var u, v fr.Element
	u.SetRandom()
	v.SetRandom()
	var P, Q bls12381.G2Affine
	P.ScalarMultiplication(&G, u.BigInt(new(big.Int)))
	Q.ScalarMultiplication(&G, v.BigInt(new(big.Int)))
	var expected bls12381.G2Affine
	expected.Add(&P, &Q)
	circuit := ecaddG2BLSCircuit{}
	witness := ecaddG2BLSCircuit{
		X0:       sw_bls12381.NewG2Affine(P),
		X1:       sw_bls12381.NewG2Affine(Q),
		Expected: sw_bls12381.NewG2Affine(expected),
	}
	return &circuit, &witness
}

func TestECAddG2BLSCircuitShort(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECAddG2BLS()
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECAddG2BLSCircuitFull(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECAddG2BLS()
	assert.CheckCircuit(circuit, test.WithValidAssignment(witness))
}

// 14: G2 MSM
type ecmsmg2BLSCircuit struct {
	Points  [10]sw_bls12381.G2Affine
	Scalars [10]sw_bls12381.Scalar
	Res     sw_bls12381.G2Affine
	n       int
}

func (c *ecmsmg2BLSCircuit) Define(api frontend.API) error {
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		panic(err)
	}
	ps := make([]*sw_bls12381.G2Affine, c.n)
	for i := range c.n {
		ps[i] = &c.Points[i]
	}
	ss := make([]*sw_bls12381.Scalar, c.n)
	for i := range c.n {
		ss[i] = &c.Scalars[i]
	}
	res := ECMSMG2BLS(api, ps, ss)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestECMSMG2BLSCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	P := make([]bls12381.G2Affine, 10)
	S := make([]fr.Element, 10)
	for i := 0; i < 10; i++ {
		S[i].SetRandom()
		P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	}

	var cP [10]sw_bls12381.G2Affine
	for i := range cP {
		cP[i] = sw_bls12381.NewG2Affine(P[i])
	}
	var cS [10]emulated.Element[emulated.BLS12381Fr]
	for i := range cS {
		cS[i] = emulated.ValueOf[emulated.BLS12381Fr](S[i])
	}

	for i := 1; i < 11; i++ {
		var res bls12381.G2Affine
		_, err := res.MultiExp(P[:i], S[:i], ecc.MultiExpConfig{})
		assert.NoError(err)
		err = test.IsSolved(&ecmsmg2BLSCircuit{n: i}, &ecmsmg2BLSCircuit{
			n:       i,
			Points:  cP,
			Scalars: cS,
			Res:     sw_bls12381.NewG2Affine(res),
		}, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}

// 15: multi-pairing check
type ecPairBLSBatchCircuit struct {
	P  sw_bls12381.G1Affine
	NP sw_bls12381.G1Affine
	DP sw_bls12381.G1Affine
	Q  sw_bls12381.G2Affine
	n  int
}

func (c *ecPairBLSBatchCircuit) Define(api frontend.API) error {
	Q := make([]*sw_bls12381.G2Affine, c.n)
	for i := range Q {
		Q[i] = &c.Q
	}
	switch c.n {
	case 2:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP}, Q)
	case 3:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.NP, &c.NP, &c.DP}, Q)
	case 4:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP, &c.P, &c.NP}, Q)
	case 5:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP, &c.NP, &c.NP, &c.DP}, Q)
	case 6:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP, &c.P, &c.NP, &c.P, &c.NP}, Q)
	case 7:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP, &c.P, &c.NP, &c.NP, &c.NP, &c.DP}, Q)
	case 8:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP, &c.P, &c.NP, &c.P, &c.NP, &c.P, &c.NP}, Q)
	case 9:
		ECPairBLS(api, []*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.P, &c.NP, &c.P, &c.NP, &c.P, &c.NP, &c.NP, &c.NP, &c.DP}, Q)
	default:
		return fmt.Errorf("not handled %d", c.n)
	}
	return nil
}

func TestECPairBLSBLSMulBatch(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, p, q := bls12381.Generators()

	var u, v fr.Element
	u.SetRandom()
	v.SetRandom()

	p.ScalarMultiplication(&p, u.BigInt(new(big.Int)))
	q.ScalarMultiplication(&q, v.BigInt(new(big.Int)))

	var dp, np bls12381.G1Affine
	dp.Double(&p)
	np.Neg(&p)

	for i := 2; i < 10; i++ {
		err := test.IsSolved(&ecPairBLSBatchCircuit{n: i}, &ecPairBLSBatchCircuit{
			n:  i,
			P:  sw_bls12381.NewG1Affine(p),
			NP: sw_bls12381.NewG1Affine(np),
			DP: sw_bls12381.NewG1Affine(dp),
			Q:  sw_bls12381.NewG2Affine(q),
		}, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}

// 16: mapToG1 check
type eCMapToG1BLSCircuit struct {
	A emulated.Element[emulated.BLS12381Fp]
	R sw_bls12381.G1Affine
}

func (c *eCMapToG1BLSCircuit) Define(api frontend.API) error {

	g, err := sw_bls12381.NewG1(api)
	if err != nil {
		return fmt.Errorf("new G1: %w", err)
	}
	r := ECMapToG1BLS(api, &c.A)
	g.AssertIsEqual(r, &c.R)

	return nil
}

func TestECMapToG1(t *testing.T) {

	assert := test.NewAssert(t)
	var a fp.Element
	a.SetRandom()
	g := bls12381.MapToG1(a)

	witness := eCMapToG1BLSCircuit{
		A: emulated.ValueOf[emulated.BLS12381Fp](a.String()),
		R: sw_bls12381.NewG1Affine(g),
	}

	err := test.IsSolved(&eCMapToG1BLSCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type ECMapToG2BLSCircuit struct {
	A fields_bls12381.E2
	R sw_bls12381.G2Affine
}

func (c *ECMapToG2BLSCircuit) Define(api frontend.API) error {
	g, err := sw_bls12381.NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2: %w", err)
	}
	r := ECMapToG2BLS(api, &c.A)
	g.AssertIsEqual(r, &c.R)

	return nil
}

func TestECMapToG2(t *testing.T) {
	assert := test.NewAssert(t)
	var a bls12381.E2
	a.A0.SetRandom()
	a.A1.SetRandom()
	g := bls12381.MapToG2(a)

	witness := ECMapToG2BLSCircuit{
		A: fields_bls12381.FromE2(&a),
		R: sw_bls12381.NewG2Affine(g),
	}

	err := test.IsSolved(&ECMapToG2BLSCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
