package main

import (
	"fmt"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/compress/lzss_v2"
)

// executable to generate the constraints for the circuit and store it
func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	cs, err := lzss_v2.BenchCompressionE2ECompilation(nil, "../../test_cases/large")
	check(err)

	fmt.Println(cs.GetNbConstraints(), "constraints")
	check(compress.GzWrite("600kb.gz", cs))
}
