// Package benchmark internal benchmarks
package main

import (
	"encoding/csv"
	"os"
	"runtime"
	"strconv"
	"time"

	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bn256/fr"
)

// /!\ internal use /!\

func main() {
	n, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}

	// generate dummy circuit
	pk, r1cs, input := generateCircuit(n)
	_r1cs := r1cs.(*backend_bn256.R1CS)

	// measure proving time
	start := time.Now()
	_, _ = groth16.Prove(r1cs, pk, input)
	took := time.Since(start)

	// check memory usage, max ram requested from OS
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	bData := benchData{
		NbCpus:         runtime.NumCPU(),
		NbCoefficients: len(_r1cs.Coefficients),
		NbConstraints:  _r1cs.NbConstraints,
		NbWires:        _r1cs.NbWires,
		RunTime:        took.Milliseconds(),
		MaxRAM:         (m.Sys / 1024 / 1024),
	}

	// write to stdout
	w := csv.NewWriter(os.Stdout)
	if err := w.Write(bData.headers()); err != nil {
		panic(err)
	}
	if err := w.Write(bData.values()); err != nil {
		panic(err)
	}
	w.Flush()
}

type benchCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *benchCircuit) Define(ctx *frontend.Context, cs *frontend.CS) error {
	nbConstraints, _ := ctx.Value(nbConstraintKey)
	for i := 0; i < nbConstraints.(int); i++ {
		circuit.X = cs.MUL(circuit.X, circuit.X)
	}
	cs.MUSTBE_EQ(circuit.X, circuit.Y)
	return nil
}

func (circuit *benchCircuit) PostInit(ctx *frontend.Context) error {
	return nil
}

type _nbConstraintKey int

var nbConstraintKey _nbConstraintKey

func generateCircuit(nbConstraints int) (groth16.ProvingKey, r1cs.R1CS, map[string]interface{}) {
	var circuit benchCircuit
	ctx := frontend.NewContext(gurvy.BN256)
	ctx.Set(nbConstraintKey, nbConstraints)

	r1cs, err := frontend.Compile(ctx, &circuit)
	if err != nil {
		panic(err)
	}

	// compute expected Y
	var expectedY fr.Element
	expectedY.SetInterface(2)
	for i := 0; i < nbConstraints; i++ {
		expectedY.MulAssign(&expectedY)
	}
	solution := make(map[string]interface{})
	solution["X"] = 2
	solution["Y"] = expectedY

	// ---------------------------------------------------------------------------------------------
	//  setup
	pk := groth16.DummySetup(r1cs)
	return pk, r1cs, solution
}

type benchData struct {
	NbConstraints  int
	NbWires        int
	NbCoefficients int
	MaxRAM         uint64
	RunTime        int64
	NbCpus         int
}

func (bData benchData) headers() []string {
	return []string{"nbConstraints", "nbWires", "nbCoefficients", "ram(mb)", "time(ms)", "nbCpus"}
}
func (bData benchData) values() []string {
	return []string{
		strconv.Itoa(bData.NbConstraints),
		strconv.Itoa(bData.NbWires),
		strconv.Itoa(bData.NbCoefficients),
		strconv.Itoa(int(bData.MaxRAM)),
		strconv.Itoa(int(bData.RunTime)),
		strconv.Itoa(bData.NbCpus),
	}
}
