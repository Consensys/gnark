package main

import (
	"bytes"
	"fmt"
	"os"
	"reflect"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/curve"
	"github.com/consensys/gnark/internal/generators/testcircuits/circuits"
	"github.com/consensys/gnark/internal/utils/encoding/gob"
)

//go:generate go run -tags bls377,debug . ../../../backend/groth16/testdata/bls377
//go:generate go run -tags bls381,debug . ../../../backend/groth16/testdata/bls381
//go:generate go run -tags bn256,debug . ../../../backend/groth16/testdata/bn256
func main() {
	fmt.Println()
	fmt.Println("generating test circuits for ", curve.ID.String())
	fmt.Println()
	for k, v := range circuits.Circuits {
		// test r1cs serialization
		var bytes bytes.Buffer
		if err := gob.Serialize(&bytes, v.R1CS, curve.ID); err != nil {
			panic("serializaing R1CS shouldn't output an error")
		}
		var r1cs backend.R1CS
		if err := gob.Deserialize(&bytes, &r1cs, curve.ID); err != nil {
			panic("deserializaing R1CS shouldn't output an error")
		}
		if !reflect.DeepEqual(v.R1CS, &r1cs) {
			panic("round trip (de)serializaiton of R1CS failed")
		}

		// serialize test circuits to disk
		if err := os.MkdirAll(os.Args[1], 0700); err != nil {
			panic(err)
		}
		// if err := os.MkdirAll(os.Args[2], 0700); err != nil {
		// 	panic(err)
		// }
		names := []string{
			fmt.Sprintf("%s/%s.", os.Args[1], k),
			// fmt.Sprintf("%s/%s.", os.Args[2], k),
		}
		for _, fName := range names {
			fmt.Println("generating", fName)
			if err := gob.Write(fName+"r1cs", v.R1CS, curve.ID); err != nil {
				panic(err)
			}
			if err := v.Good.WriteFile(fName + "good"); err != nil {
				panic(err)
			}
			if err := v.Bad.WriteFile(fName + "bad"); err != nil {
				panic(err)
			}
		}
	}
}
