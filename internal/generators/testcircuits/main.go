package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark/internal/generators/testcircuits/circuits"
	"github.com/consensys/gnark/internal/utils/encoding/gob"
	"github.com/consensys/gurvy"
)

//go:generate go run -tags debug . ./generated
func main() {
	fmt.Println()
	fmt.Println("generating test circuits")
	fmt.Println()
	os.RemoveAll(os.Args[1])
	if err := os.MkdirAll(os.Args[1], 0700); err != nil {
		panic(err)
	}
	for k, v := range circuits.Circuits {
		// test r1cs serialization
		// fmt.Println("test serialization", k)
		// var bytes bytes.Buffer
		// if err := gob.Serialize(&bytes, v.R1CS, gurvy.UNKNOWN); err != nil {
		// 	panic("serializaing R1CS shouldn't output an error")
		// }
		// var r1cs frontend.R1CS
		// if err := gob.Deserialize(&bytes, &r1cs, gurvy.UNKNOWN); err != nil {
		// 	panic("deserializaing R1CS shouldn't output an error")
		// }
		// if !reflect.DeepEqual(v.R1CS, &r1cs) {
		// 	panic("round trip (de)serializaiton of R1CS failed")
		// }

		// serialize test circuits to disk

		// if err := os.MkdirAll(os.Args[2], 0700); err != nil {
		// 	panic(err)
		// }
		names := []string{
			fmt.Sprintf("%s/%s.", os.Args[1], k),
			// fmt.Sprintf("%s/%s.", os.Args[2], k),
		}
		for _, fName := range names {
			fmt.Println("generating", fName)
			if err := gob.Write(fName+"r1cs", v.R1CS, gurvy.UNKNOWN); err != nil {
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
