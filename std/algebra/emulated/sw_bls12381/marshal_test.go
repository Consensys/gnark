package sw_bls12381

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type unmarshalCircuit struct {
	InBaseField []uints.U8
	RBaseField  emulated.Element[BaseField]

	InScalarField []uints.U8
	RScalarField  emulated.Element[ScalarField]
}

func (c *unmarshalCircuit) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return err
	}

	{
		r, err := Unmarshal[BaseField](api, c.InBaseField)
		if err != nil {
			return err
		}
		g.curveF.AssertIsEqual(&c.RBaseField, r)
	}
	{
		r, err := Unmarshal[ScalarField](api, c.InScalarField)
		if err != nil {
			return err
		}
		sApi, err := emulated.NewField[ScalarField](api)
		if err != nil {
			return err
		}
		sApi.AssertIsEqual(&c.RScalarField, r)
	}

	return nil
}

func TestUnmarshal(t *testing.T) {
	assert := test.NewAssert(t)
	nbBytesFp := fp.Bytes
	nbBytesFr := fr.Bytes

	var witness, circuit unmarshalCircuit
	{
		var a fp.Element
		a.SetRandom()
		aMarshalled := a.Marshal()

		witness.InBaseField = make([]uints.U8, nbBytesFp)
		circuit.InBaseField = make([]uints.U8, nbBytesFp)
		for i := 0; i < nbBytesFp; i++ {
			witness.InBaseField[i] = uints.NewU8(aMarshalled[i])
		}
		witness.RBaseField = emulated.ValueOf[BaseField](a)
	}
	{
		var a fr.Element
		a.SetRandom()
		aMarshalled := a.Marshal()

		witness.InScalarField = make([]uints.U8, nbBytesFr)
		circuit.InScalarField = make([]uints.U8, nbBytesFr)
		for i := 0; i < nbBytesFr; i++ {
			witness.InScalarField[i] = uints.NewU8(aMarshalled[i])
		}
		witness.RScalarField = emulated.ValueOf[ScalarField](a)
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type marshalCircuit struct {
	InBaseField emulated.Element[BaseField]
	RBaseField  []uints.U8

	InScalarField emulated.Element[ScalarField]
	RScalarField  []uints.U8
}

func (c *marshalCircuit) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return err
	}

	{
		r, err := Marshal[BaseField](api, &c.InBaseField)
		if err != nil {
			return err
		}
		for i := 0; i < len(c.RBaseField); i++ {
			g.api.AssertIsEqual(c.RBaseField[i].Val, r[i].Val)
		}
	}
	{
		r, err := Marshal[ScalarField](api, &c.InScalarField)
		if err != nil {
			return err
		}
		for i := 0; i < len(c.RScalarField); i++ {
			g.api.AssertIsEqual(c.RScalarField[i].Val, r[i].Val)
		}
	}

	return nil
}

func TestMarshal(t *testing.T) {
	assert := test.NewAssert(t)
	nbBytesFp := fp.Bytes
	nbBytesFr := fr.Bytes

	var witness, circuit marshalCircuit
	{
		var a fp.Element
		a.SetRandom()
		aMarshalled := a.Marshal()

		witness.InBaseField = emulated.ValueOf[BaseField](a)
		witness.RBaseField = make([]uints.U8, nbBytesFp)
		circuit.InBaseField = emulated.ValueOf[BaseField](0)
		for i := 0; i < nbBytesFp; i++ {
			witness.RBaseField[i] = uints.NewU8(aMarshalled[i])
		}
	}
	{
		var a fr.Element
		a.SetRandom()
		aMarshalled := a.Marshal()

		witness.InScalarField = emulated.ValueOf[ScalarField](a)
		witness.RScalarField = make([]uints.U8, nbBytesFr)
		circuit.InScalarField = emulated.ValueOf[ScalarField](0)
		for i := 0; i < nbBytesFr; i++ {
			witness.RScalarField[i] = uints.NewU8(aMarshalled[i])
		}
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
