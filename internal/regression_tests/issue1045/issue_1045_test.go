package issue1045

import (
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

const (
	explicitHintName  = "github.com/consensys/gnark/internal/regression_tests/issue1045.ExplicitHint"
	anonymousHintName = "github.com/consensys/gnark/internal/regression_tests/issue1045.glob..func1"
)

func ExplicitHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	outputs[0].Set(inputs[0])
	return nil
}

var AnonymousHint = func(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	outputs[0].Set(inputs[0])
	return nil
}

func TestGetHintname(t *testing.T) {
	if resolvedExplicitHintName := solver.GetHintName(ExplicitHint); resolvedExplicitHintName != explicitHintName {
		t.Errorf("expected %s, got %s", explicitHintName, resolvedExplicitHintName)
	}
	if resolvedAnonymousHintName := solver.GetHintName(AnonymousHint); resolvedAnonymousHintName != anonymousHintName {
		t.Errorf("expected %s, got %s", anonymousHintName, resolvedAnonymousHintName)
	}
}

type Circuit struct {
	In1, In2 frontend.Variable `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
	res1, err := api.Compiler().NewHint(ExplicitHint, 1, c.In1)
	if err != nil {
		return err
	}
	res2, err := api.Compiler().NewHint(AnonymousHint, 1, c.In2)
	if err != nil {
		return err
	}
	api.AssertIsEqual(res1[0], c.In1)
	api.AssertIsEqual(res2[0], c.In2)
	return nil
}

func TestCircuitCompile(t *testing.T) {
	t.Skip("test used only to generate testdata")
	assert := test.NewAssert(t)
	for _, bb := range []struct {
		builder frontend.NewBuilder
		tag     string
	}{{scs.NewBuilder, "scs"}, {r1cs.NewBuilder, "r1cs"}} {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), bb.builder, &Circuit{})
		assert.NoError(err)
		f, err := os.Create("testdata/issue1045." + bb.tag)
		assert.NoError(err)
		defer f.Close()
		_, err = ccs.WriteTo(f)
		assert.NoError(err)
	}
}

func TestCircuitProveDeserializedGroth16(t *testing.T) {
	assert := test.NewAssert(t)
	ccs := groth16.NewCS(ecc.BN254)
	f, err := os.Open("testdata/issue1045.r1cs")
	assert.NoError(err)
	_, err = ccs.ReadFrom(f)
	assert.NoError(err)

	wit, err := witness.New(ecc.BN254.ScalarField())
	assert.NoError(err)
	filler := make(chan any)
	go func() {
		filler <- fr_bn254.NewElement(123)
		filler <- fr_bn254.NewElement(333)
		close(filler)
	}()
	err = wit.Fill(2, 0, filler)
	assert.NoError(err)
	err = ccs.IsSolved(wit, solver.WithHints(ExplicitHint, AnonymousHint))
	assert.NoError(err)
}

func TestCircuitProveDeserializedPlonk(t *testing.T) {
	assert := test.NewAssert(t)
	ccs := plonk.NewCS(ecc.BN254)
	f, err := os.Open("testdata/issue1045.scs")
	assert.NoError(err)
	_, err = ccs.ReadFrom(f)
	assert.NoError(err)

	wit, err := witness.New(ecc.BN254.ScalarField())
	assert.NoError(err)
	filler := make(chan any)
	go func() {
		filler <- fr_bn254.NewElement(123)
		filler <- fr_bn254.NewElement(333)
		close(filler)
	}()
	err = wit.Fill(2, 0, filler)
	assert.NoError(err)
	err = ccs.IsSolved(wit, solver.WithHints(ExplicitHint, AnonymousHint))
	assert.NoError(err)
}
