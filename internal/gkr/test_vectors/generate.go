package main

import gkr "github.com/consensys/gnark/internal/gkr/small_rational"

func main() {
	assertNoError(gkr.GenerateSumcheckVectors())
	assertNoError(gkr.GenerateVectors())
}

func assertNoError(err error) {
	if err != nil {
		panic(err)
	}
}
