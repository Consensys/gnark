package main

import "github.com/consensys/gnark/examples/p256"

func main() {
	p256.Groth16Setup("build/")
	p256.Groth16Prove("build/")
}