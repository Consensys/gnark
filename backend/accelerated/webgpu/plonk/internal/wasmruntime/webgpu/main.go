//go:build js && wasm

package main

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/accelerated/webgpu/internal/wasmruntime"
	webgpuplonk "github.com/consensys/gnark/backend/accelerated/webgpu/plonk"
	gnarkplonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

func main() {
	if err := wasmruntime.Install(wasmruntime.Config[gnarkplonk.ProvingKey, gnarkplonk.VerifyingKey, gnarkplonk.Proof]{
		GlobalName: "gnarkPlonkRuntimeWebGPU",
		SupportedCurves: map[string]ecc.ID{
			"bn254":     ecc.BN254,
			"bls12_377": ecc.BLS12_377,
			"bls12_381": ecc.BLS12_381,
		},
		CSFactory:    gnarkplonk.NewCS,
		PKFactory:    webgpuplonk.NewProvingKey,
		VKFactory:    gnarkplonk.NewVerifyingKey,
		ProofFactory: gnarkplonk.NewProof,
		ReadProvingKey: func(pk gnarkplonk.ProvingKey, format string, data []byte) error {
			switch format {
			case "serialized":
				if _, err := pk.ReadFrom(bytes.NewReader(data)); err != nil {
					return fmt.Errorf("read pk: %w", err)
				}
			case "unsafe":
				if _, err := pk.UnsafeReadFrom(bytes.NewReader(data)); err != nil {
					return fmt.Errorf("read pk unsafe: %w", err)
				}
			default:
				return fmt.Errorf("unsupported proving key format %q", format)
			}
			return nil
		},
		Prepare:       webgpuplonk.Prepare,
		PrepareWithCS: webgpuplonk.PrepareWithCS,
		Prove: func(ccs constraint.ConstraintSystem, pk gnarkplonk.ProvingKey, fullWitness witness.Witness) (gnarkplonk.Proof, error) {
			return webgpuplonk.Prove(ccs, pk, fullWitness)
		},
		Verify: func(proof gnarkplonk.Proof, vk gnarkplonk.VerifyingKey, publicWitness witness.Witness) error {
			return gnarkplonk.Verify(proof, vk, publicWitness)
		},
	}); err != nil {
		panic(err)
	}
}
