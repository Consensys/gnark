package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark/encoding/gob"
	"github.com/consensys/gnark/internal/generators/testcircuits/circuits"
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
		names := []string{
			fmt.Sprintf("%s/%s.", os.Args[1], k),
			// fmt.Sprintf("%s/%s.", os.Args[2], k),
		}
		for _, fName := range names {
			fmt.Println("generating", fName)
			if err := gob.Write(fName+"r1cs", v.R1CS, gurvy.UNKNOWN); err != nil {
				panic(err)
			}
			if err := gob.WriteMap(fName+"good", v.Good); err != nil {
				panic(err)
			}
			if err := gob.WriteMap(fName+"bad", v.Bad); err != nil {
				panic(err)
			}
		}
	}
}
