package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bn256/fr"
)

// if you want to change the curve type in this benchmark
// modify the gurvy/bn256/fr import too to be able to compute a correct solution
const curveID = gurvy.BN256

func main() {
	n, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("usage is ./benchmark nbConstraints")
		os.Exit(-1)
	}

	// generate dummy circuit and solution
	pk, r1cs := generateCircuit(n)
	input := generateSolution(n)

	// measure proving time
	start := time.Now()
	_, _ = groth16.Prove(r1cs, pk, input)
	took := time.Since(start)

	// check memory usage, max ram requested from OS
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	bData := benchData{
		NbCpus:         runtime.NumCPU(),
		NbCoefficients: r1cs.GetNbCoefficients(),
		NbConstraints:  r1cs.GetNbConstraints(),
		NbWires:        r1cs.GetNbWires(),
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

// benchCircuit is a simple circuit that checks X*X*X*X*X... == Y
type benchCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
	n int
}

func (circuit *benchCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	for i := 0; i < circuit.n; i++ {
		circuit.X = cs.Mul(circuit.X, circuit.X)
	}
	cs.AssertIsEqual(circuit.X, circuit.Y)
	return nil
}

func generateCircuit(nbConstraints int) (groth16.ProvingKey, r1cs.R1CS) {
	var circuit benchCircuit
	circuit.n = nbConstraints

	r1cs, err := frontend.Compile(curveID, &circuit)
	if err != nil {
		panic(err)
	}

	// dummy setup will not compute a verifying key and just sets random value in the proving key
	pk := groth16.DummySetup(r1cs)
	return pk, r1cs
}

func generateSolution(nbConstraints int) (witness benchCircuit) {
	witness.n = nbConstraints

	// compute expected Y
	var expectedY fr.Element
	expectedY.SetInterface(2)
	for i := 0; i < nbConstraints; i++ {
		expectedY.MulAssign(&expectedY)
	}
	witness.X.Assign(2)
	witness.Y.Assign(expectedY)

	return
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
