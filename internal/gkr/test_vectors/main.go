package main

import (
	"github.com/consensys/gnark/internal/gkr/test_vectors/gkr"
	"github.com/consensys/gnark/internal/gkr/test_vectors/sumcheck"
)

func main() {
	assertNoError(sumcheck.GenerateVectors())
	assertNoError(gkr.GenerateVectors())
}

func assertNoError(err error) {
	if err != nil {
		panic(err)
	}
}
