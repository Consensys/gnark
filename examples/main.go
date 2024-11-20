package main

import (
	"os"

	"github.com/consensys/gnark/examples/p256"
)

func main() {
	if _, err := os.Stat("build/"); os.IsNotExist(err) {
		p256.Groth16Setup("build/")
	}
	p256.Groth16Prove("build/")
}
