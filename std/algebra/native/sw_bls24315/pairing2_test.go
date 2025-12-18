package sw_bls24315

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func randomG1G2Affines() (bls24315.G1Affine, bls24315.G2Affine) {
	_, _, G1AffGen, G2AffGen := bls24315.Generators()
	mod := bls24315.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	s2, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	var p bls24315.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bls24315.G2Affine
	q.ScalarMultiplication(&G2AffGen, s2)
	return p, q
}

type MuxCircuitTest struct {
	Selector frontend.Variable
	Inputs   [8]G1Affine
	Expected G1Affine
}

func (c *MuxCircuitTest) Define(api frontend.API) error {
	cr, err := NewCurve(api)
	if err != nil {
		return err
	}
	els := make([]*G1Affine, len(c.Inputs))
	for i := range c.Inputs {
		els[i] = &c.Inputs[i]
	}
	res := cr.Mux(c.Selector, els...)
	cr.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestMux(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MuxCircuitTest{}
	r := make([]fr_bls24315.Element, len(circuit.Inputs))
	for i := range r {
		r[i].SetRandom()
	}
	selector, _ := rand.Int(rand.Reader, big.NewInt(int64(len(r))))
	expectedR := r[selector.Int64()]
	expected := new(bls24315.G1Affine).ScalarMultiplicationBase(expectedR.BigInt(new(big.Int)))
	witness := MuxCircuitTest{
		Selector: selector,
		Expected: NewG1Affine(*expected),
	}
	for i := range r {
		eli := new(bls24315.G1Affine).ScalarMultiplicationBase(r[i].BigInt(new(big.Int)))
		witness.Inputs[i] = NewG1Affine(*eli)
	}
	err := test.IsSolved(&circuit, &witness, ecc.BW6_633.ScalarField())
	assert.NoError(err)
}

type MuxG2GtCircuit struct {
	InG2       []G2Affine
	InGt       []GT
	SelG2      frontend.Variable
	SelGt      frontend.Variable
	ExpectedG2 G2Affine
	ExpectedGt GT
}

func (c *MuxG2GtCircuit) Define(api frontend.API) error {
	pairing := NewPairing(api)
	var inG2 []*G2Affine
	for i := range c.InG2 {
		inG2 = append(inG2, &c.InG2[i])
	}
	var inGt []*GT
	for i := range c.InGt {
		inGt = append(inGt, &c.InGt[i])
	}
	g2 := pairing.MuxG2(c.SelG2, inG2...)
	gt := pairing.MuxGt(c.SelGt, inGt...)
	if len(c.InG2) == 0 {
		if g2 != nil {
			return fmt.Errorf("mux G2: expected nil, got %v", g2)
		}
	} else {
		c.ExpectedG2.P.AssertIsEqual(api, g2.P)
	}
	if len(c.InGt) == 0 {
		if gt != nil {
			return fmt.Errorf("mux Gt: expected nil, got %v", gt)
		}
	} else {
		pairing.AssertIsEqual(gt, &c.ExpectedGt)
	}
	return nil
}

func TestPairingMuxes(t *testing.T) {
	assert := test.NewAssert(t)
	var err error
	for _, nbPairs := range []int{0, 1, 2, 3, 4, 5} {
		assert.Run(func(assert *test.Assert) {
			g2s := make([]bls24315.G2Affine, nbPairs)
			gts := make([]bls24315.GT, nbPairs)
			var p bls24315.G1Affine
			witG2s := make([]G2Affine, nbPairs)
			witGts := make([]GT, nbPairs)
			for i := range nbPairs {
				p, g2s[i] = randomG1G2Affines()
				gts[i], err = bls24315.Pair([]bls24315.G1Affine{p}, []bls24315.G2Affine{g2s[i]})
				assert.NoError(err)
				witG2s[i] = NewG2Affine(g2s[i])
				witGts[i] = NewGTEl(gts[i])
			}
			circuit := MuxG2GtCircuit{InG2: make([]G2Affine, nbPairs), InGt: make([]GT, nbPairs)}
			var witness MuxG2GtCircuit
			if nbPairs > 0 {
				selG2, err := rand.Int(rand.Reader, big.NewInt(int64(nbPairs)))
				assert.NoError(err)
				selGt, err := rand.Int(rand.Reader, big.NewInt(int64(nbPairs)))
				assert.NoError(err)
				expectedG2 := witG2s[selG2.Int64()]
				expectedGt := witGts[selGt.Int64()]
				witness = MuxG2GtCircuit{
					InG2:       witG2s,
					InGt:       witGts,
					SelG2:      selG2,
					SelGt:      selGt,
					ExpectedG2: expectedG2,
					ExpectedGt: expectedGt,
				}
			} else {
				witness = MuxG2GtCircuit{
					InG2:       witG2s,
					InGt:       witGts,
					SelG2:      big.NewInt(0),
					SelGt:      big.NewInt(0),
					ExpectedG2: NewG2Affine(bls24315.G2Affine{}),
					ExpectedGt: NewGTEl(bls24315.GT{}),
				}
			}
			err = test.IsSolved(&circuit, &witness, ecc.BW6_761.ScalarField())
			assert.NoError(err)
		}, fmt.Sprintf("nbPairs=%d", nbPairs))
	}
}
