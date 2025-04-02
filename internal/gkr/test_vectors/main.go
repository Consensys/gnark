package main

import "github.com/consensys/gnark/internal/gkr/test_vectors/sumcheck"

func main() {
	assertNoError(sumcheck.Generate())
}

func assertNoError(err error) {
	if err != nil {
		panic(err)
	}
}
