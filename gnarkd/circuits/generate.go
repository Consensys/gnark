package main

import (
	"os"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gnarkd/circuits/bn256/cubic"
	"github.com/consensys/gurvy"
)

//go:generate go run generate.go
func main() {
	var circuit cubic.Circuit
	r1cs, _ := frontend.Compile(gurvy.BN256, &circuit)

	{
		f, _ := os.Create("bn256/cubic/cubic.r1cs")
		r1cs.WriteTo(f)
		f.Close()
	}

	pk, vk, _ := groth16.Setup(r1cs)
	{
		f, _ := os.Create("bn256/cubic/cubic.pk")
		pk.WriteTo(f)
		f.Close()
	}
	{
		f, _ := os.Create("bn256/cubic/cubic.vk")
		vk.WriteTo(f)
		f.Close()
	}
}
