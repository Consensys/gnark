package circuits

import "github.com/consensys/gnark/frontend"

type commitCircuit struct {
	Public frontend.Variable `gnark:",public"`
	X      frontend.Variable
}

func (circuit *commitCircuit) Define(api frontend.API) error {
	api.AssertIsDifferent(circuit.Public, 0)
	commitment, err := api.(frontend.Committer).Commit(circuit.X, circuit.Public, 5)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)
	a := api.Mul(circuit.X, circuit.X)
	for i := 0; i < 10; i++ {
		a = api.Mul(a, circuit.X)
	}
	c := api.Add(a, circuit.X)
	api.AssertIsDifferent(c, a)
	return nil
}

func init() {

	var circuit, good, bad commitCircuit

	good.X = 3
	good.Public = 16

	bad.X = 4
	bad.Public = 0

	addEntry("commit", &circuit, &good, &bad, nil)
}
