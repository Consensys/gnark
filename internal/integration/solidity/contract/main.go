package main

import (
	"os"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/examples/cubic"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy/ecc"
)

// run this from /integration/solidity to regenerate files
// note: this is not in go generate format to avoid solc dependency in circleCI for now.
// go run contract/main.go && abigen --sol contract.sol --pkg solidity --out solidity.go
func main() {
	var circuit cubic.Circuit

	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}
	{
		f, err := os.Create("cubic.vk")
		if err != nil {
			panic(err)
		}
		_, err = vk.WriteRawTo(f)
		if err != nil {
			panic(err)
		}
	}
	{
		f, err := os.Create("cubic.pk")
		if err != nil {
			panic(err)
		}
		_, err = pk.WriteRawTo(f)
		if err != nil {
			panic(err)
		}
	}

	{
		f, err := os.Create("contract.sol")
		if err != nil {
			panic(err)
		}
		err = vk.ExportSolidity(f)
		if err != nil {
			panic(err)
		}
	}

}
