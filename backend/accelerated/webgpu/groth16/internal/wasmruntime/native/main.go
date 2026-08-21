//go:build js && wasm

package main

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark/backend/accelerated/webgpu/internal/wasmruntime"
	gnarkgroth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

func main() {
	if err := wasmruntime.Install(wasmruntime.Config[gnarkgroth16.ProvingKey, gnarkgroth16.VerifyingKey, gnarkgroth16.Proof]{
		GlobalName:   "gnarkGroth16RuntimeNative",
		CSFactory:    gnarkgroth16.NewCS,
		PKFactory:    gnarkgroth16.NewProvingKey,
		VKFactory:    gnarkgroth16.NewVerifyingKey,
		ProofFactory: gnarkgroth16.NewProof,
		ReadProvingKey: func(pk gnarkgroth16.ProvingKey, format string, data []byte) error {
			switch format {
			case "serialized":
				if _, err := pk.ReadFrom(bytes.NewReader(data)); err != nil {
					return fmt.Errorf("read pk: %w", err)
				}
			case "dump":
				if err := pk.ReadDump(bytes.NewReader(data)); err != nil {
					return fmt.Errorf("read pk dump: %w", err)
				}
			default:
				return fmt.Errorf("unsupported proving key format %q", format)
			}
			return nil
		},
		Prove: func(ccs constraint.ConstraintSystem, pk gnarkgroth16.ProvingKey, fullWitness witness.Witness) (gnarkgroth16.Proof, error) {
			return gnarkgroth16.Prove(ccs, pk, fullWitness)
		},
		Verify: func(proof gnarkgroth16.Proof, vk gnarkgroth16.VerifyingKey, publicWitness witness.Witness) error {
			return gnarkgroth16.Verify(proof, vk, publicWitness)
		},
	}); err != nil {
		panic(err)
	}
}
