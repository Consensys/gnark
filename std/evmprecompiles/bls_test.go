package evmprecompiles

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type ecaddBLSCircuit struct {
	X0       sw_emulated.AffinePoint[emulated.BLS12381Fp]
	X1       sw_emulated.AffinePoint[emulated.BLS12381Fp]
	Expected sw_emulated.AffinePoint[emulated.BLS12381Fp]
}

func (c *ecaddBLSCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return err
	}
	res := ECAddBLS(api, &c.X0, &c.X1)
	curve.AssertIsEqual(res, &c.Expected)
	return nil
}

func testRoutineECAddBLS() (circ, wit frontend.Circuit) {
	_, _, G, _ := bls12381.Generators()
	var u, v fr.Element
	u.SetRandom()
	v.SetRandom()
	var P, Q bls12381.G1Affine
	P.ScalarMultiplication(&G, u.BigInt(new(big.Int)))
	Q.ScalarMultiplication(&G, v.BigInt(new(big.Int)))
	var expected bls12381.G1Affine
	expected.Add(&P, &Q)
	circuit := ecaddBLSCircuit{}
	witness := ecaddBLSCircuit{
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

func TestECAddBLSCircuitShort(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECAddBLS()
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type ecaddG2BLSCircuit struct {
	X0       sw_bls12381.G2Affine
	X1       sw_bls12381.G2Affine
	Expected sw_bls12381.G2Affine
}

func (c *ecaddG2BLSCircuit) Define(api frontend.API) error {
	g2 := sw_bls12381.NewG2(api)
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
func TestECAddBLSCircuitFull(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECAdd()
	assert.CheckCircuit(circuit, test.WithValidAssignment(witness))
}

type ecmulBLSCircuit struct {
	X0       sw_emulated.AffinePoint[emulated.BLS12381Fp]
	U        emulated.Element[emulated.BLS12381Fr]
	Expected sw_emulated.AffinePoint[emulated.BLS12381Fp]
}

func (c *ecmulBLSCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return err
	}
	res := ECMSMG1BLS(api,
		[]*sw_emulated.AffinePoint[emulated.BLS12381Fp]{&c.X0},
		[]*emulated.Element[emulated.BLS12381Fr]{&c.U},
	)
	curve.AssertIsEqual(res, &c.Expected)
	return nil
}

func testRoutineECMulBLS(t *testing.T) (circ, wit frontend.Circuit) {
	_, _, G, _ := bls12381.Generators()
	var u, v fr.Element
	u.SetRandom()
	v.SetRandom()
	var P bls12381.G1Affine
	P.ScalarMultiplication(&G, u.BigInt(new(big.Int)))
	var expected bls12381.G1Affine
	expected.ScalarMultiplication(&P, v.BigInt(new(big.Int)))
	circuit := ecmulBLSCircuit{}
	witness := ecmulBLSCircuit{
		X0: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](P.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](P.Y),
		},
		U: emulated.ValueOf[emulated.BLS12381Fr](v),
		Expected: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](expected.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](expected.Y),
		},
	}
	return &circuit, &witness
}

func TestECMulBLSCircuitFull(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness := testRoutineECMulBLS(t)
	assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254))
}

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

type ecmsmg1BLSCircuit struct {
	Points  []sw_emulated.AffinePoint[emulated.BLS12381Fp]
	Scalars []emulated.Element[emulated.BLS12381Fr]
	Res     sw_emulated.AffinePoint[emulated.BLS12381Fp]
}

func (c *ecmsmg1BLSCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return err
	}
	ps := make([]*sw_emulated.AffinePoint[emulated.BLS12381Fp], len(c.Points))
	for i := range c.Points {
		ps[i] = &c.Points[i]
	}
	ss := make([]*emulated.Element[emulated.BLS12381Fr], len(c.Scalars))
	for i := range c.Scalars {
		ss[i] = &c.Scalars[i]
	}
	res := ECMSMG1BLS(api, ps, ss)
	curve.AssertIsEqual(res, &c.Res)
	return nil
}

func TestECMSMG1BLSCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	nbLen := 4
	P := make([]bls12381.G1Affine, nbLen)
	S := make([]fr_bls12381.Element, nbLen)
	for i := 0; i < nbLen; i++ {
		S[i].SetRandom()
		P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	}
	var res bls12381.G1Affine
	_, err := res.MultiExp(P, S, ecc.MultiExpConfig{})

	assert.NoError(err)
	cP := make([]sw_emulated.AffinePoint[emulated.BLS12381Fp], len(P))
	for i := range cP {
		cP[i] = sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](P[i].X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](P[i].Y),
		}
	}
	cS := make([]emulated.Element[emulated.BLS12381Fr], len(S))
	for i := range cS {
		cS[i] = emulated.ValueOf[emulated.BLS12381Fr](S[i])
	}
	assignment := ecmsmg1BLSCircuit{
		Points:  cP,
		Scalars: cS,
		Res: sw_emulated.AffinePoint[emulated.BLS12381Fp]{
			X: emulated.ValueOf[emulated.BLS12381Fp](res.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](res.Y),
		},
	}
	err = test.IsSolved(&ecmsmg1BLSCircuit{
		Points:  make([]sw_emulated.AffinePoint[emulated.BLS12381Fp], nbLen),
		Scalars: make([]emulated.Element[emulated.BLS12381Fr], nbLen),
	}, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
