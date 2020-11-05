package frontend_test

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

// TODO this has nothing to do here..
const n = 1000000

type benchCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *benchCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	for i := 0; i < n; i++ {
		circuit.X = cs.Mul(circuit.X, circuit.X)
	}
	cs.AssertIsEqual(circuit.X, circuit.Y)
	return nil
}

// var res r1cs.R1CS

// func BenchmarkCircuit(b *testing.B) {

// 	var circuit benchCircuit
// 	res, _ = frontend.Compile(gurvy.BN256, &circuit)

// 	var buff bytes.Buffer

// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		io.Write(&buff, res)
// 		b.StopTimer()
// 		buff.Reset()
// 		b.StartTimer()
// 	}

// }
