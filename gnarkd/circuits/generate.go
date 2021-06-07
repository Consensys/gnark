package main

import (
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/examples/cubic"
	"github.com/consensys/gnark/frontend"
)

//go:generate go run generate.go
func main() {
	var circuit cubic.Circuit
	const curve = ecc.BN254
	const backend = backend.GROTH16
	ccs, _ := frontend.Compile(curve, backend, &circuit)

	circuitDir := filepath.Join(backend.String(), curve.String(), "cubic")
	os.MkdirAll(circuitDir, 0700)

	{
		f, _ := os.Create(filepath.Join(circuitDir, "cubic"+".ccs"))
		ccs.WriteTo(f)
		f.Close()
	}

	pk, vk, _ := groth16.Setup(ccs)
	{
		f, _ := os.Create(filepath.Join(circuitDir, "cubic"+".pk"))
		pk.WriteTo(f)
		f.Close()
	}
	{
		f, _ := os.Create(filepath.Join(circuitDir, "cubic"+".vk"))
		vk.WriteTo(f)
		f.Close()
	}
}
