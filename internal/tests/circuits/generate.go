// This package contains test circuits
package main

import (
	"bytes"
	"fmt"
	"os"
	"reflect"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/curve"
	"github.com/consensys/gnark/utils/encoding/gob"
)

type testCircuit struct {
	r1cs      *backend.R1CS
	good, bad backend.Assignments
}

var circuits map[string]testCircuit

func addEntry(name string, r1cs *backend.R1CS, good, bad backend.Assignments) {
	if circuits == nil {
		circuits = make(map[string]testCircuit)
	}
	if _, ok := circuits[name]; ok {
		panic("name " + name + "already taken by another test circuit ")
	}
	circuits[name] = testCircuit{r1cs, good, bad}
}

//go:generate go run -tags bls377,debug . ../../../backend/groth16/testdata/bls377
//go:generate go run -tags bls381,debug . ../../../backend/groth16/testdata/bls381
//go:generate go run -tags bn256,debug . ../../../backend/groth16/testdata/bn256
func main() {

	for k, v := range circuits {
		// test r1cs serialization
		var bytes bytes.Buffer
		if err := gob.Serialize(&bytes, v.r1cs, curve.ID); err != nil {
			panic("serializaing R1CS shouldn't output an error")
		}
		var r1cs backend.R1CS
		if err := gob.Deserialize(&bytes, &r1cs, curve.ID); err != nil {
			panic("deserializaing R1CS shouldn't output an error")
		}
		if !reflect.DeepEqual(v.r1cs, &r1cs) {
			panic("round trip (de)serializaiton of R1CS failed")
		}

		// serialize test circuits to disk
		fName := fmt.Sprintf("%s/%s.", os.Args[1], k)
		fmt.Println("generating", fName)
		if err := gob.Write(fName+"r1cs", v.r1cs, curve.ID); err != nil {
			panic(err)
		}
		if err := v.good.Write(fName + "good"); err != nil {
			panic(err)
		}
		if err := v.bad.Write(fName + "bad"); err != nil {
			panic(err)
		}

	}
}
