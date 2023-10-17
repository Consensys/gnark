package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/compress/lzss_v1"
)

// executable to generate the constraints for the circuit and store it

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	c := lzss_v1.DecompressionTestCircuit{
		C: make([]frontend.Variable, 120000),
		D: make([]byte, 612000),
		Settings: lzss_v1.Settings{
			BackRefSettings: lzss_v1.BackRefSettings{
				NbBytesAddress: 2,
				NbBytesLength:  1,
			},
		},
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &c)
	check(err)

	fmt.Println(cs.GetNbConstraints(), "constraints")
	check(compress.GzWrite("600kb.gz", cs))
}
