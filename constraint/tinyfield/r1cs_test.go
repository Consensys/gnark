// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package cs_test

import (
	"bytes"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/backend/circuits"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	cs "github.com/consensys/gnark/constraint/tinyfield"

	fr "github.com/consensys/gnark/internal/smallfields/tinyfield"
)

func TestSerialization(t *testing.T) {

	var buffer, buffer2 bytes.Buffer

	for name := range circuits.Circuits {
		t.Run(name, func(t *testing.T) {
			tc := circuits.Circuits[name]
			if name == "range_constant" {
				return
			}

			r1cs1, err := frontend.CompileGeneric[constraint.U64](fr.Modulus(), r1cs.NewBuilder, tc.Circuit)
			if err != nil {
				t.Fatal(err)
			}
			if testing.Short() && r1cs1.GetNbConstraints() > 50 {
				return
			}

			// compile a second time to ensure determinism
			r1cs2, err := frontend.CompileGeneric[constraint.U64](fr.Modulus(), r1cs.NewBuilder, tc.Circuit)
			if err != nil {
				t.Fatal(err)
			}

			{
				buffer.Reset()
				t.Log(name)
				var err error
				var written, read int64
				written, err = r1cs1.WriteTo(&buffer)
				if err != nil {
					t.Fatal(err)
				}
				var reconstructed cs.R1CS
				read, err = reconstructed.ReadFrom(&buffer)
				if err != nil {
					t.Fatal(err)
				}
				if written != read {
					t.Fatal("didn't read same number of bytes we wrote")
				}

				// compare original and reconstructed
				if diff := cmp.Diff(r1cs1, &reconstructed,
					cmpopts.IgnoreFields(cs.R1CS{},
						"System.q",
						"field",
						"CoeffTable.mCoeffs",
						"System.lbWireLevel",
						"System.genericHint",
						"System.SymbolTable",
						"System.bitLen")); diff != "" {
					t.Fatalf("round trip mismatch (-want +got):\n%s", diff)
				}
			}

			// ensure determinism in compilation / serialization / reconstruction
			{
				buffer.Reset()
				n, err := r1cs1.WriteTo(&buffer)
				if err != nil {
					t.Fatal(err)
				}
				if n == 0 {
					t.Fatal("No bytes are written")
				}

				buffer2.Reset()
				_, err = r1cs2.WriteTo(&buffer2)
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(buffer.Bytes(), buffer2.Bytes()) {
					t.Fatal("compilation of R1CS is not deterministic")
				}

				var r, r2 cs.R1CS
				n, err = r.ReadFrom(&buffer)
				if err != nil {
					t.Fatal(nil)
				}
				if n == 0 {
					t.Fatal("No bytes are read")
				}
				_, err = r2.ReadFrom(&buffer2)
				if err != nil {
					t.Fatal(nil)
				}

				if !reflect.DeepEqual(r, r2) {
					t.Fatal("compilation of R1CS is not deterministic (reconstruction)")
				}
			}
		})

	}
}

const n = 10000

type circuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *circuit) Define(api frontend.API) error {
	for i := 0; i < n; i++ {
		circuit.X = api.Add(api.Mul(circuit.X, circuit.X), circuit.X, 42)
	}
	api.AssertIsEqual(circuit.X, circuit.Y)
	return nil
}

func BenchmarkSolve(b *testing.B) {

	var w circuit
	w.X = 1
	w.Y = 1
	witness, err := frontend.NewWitness(&w, fr.Modulus())
	if err != nil {
		b.Fatal(err)
	}

	b.Run("scs", func(b *testing.B) {
		var c circuit
		ccs, err := frontend.CompileGeneric[constraint.U64](fr.Modulus(), scs.NewBuilder, &c)
		if err != nil {
			b.Fatal(err)
		}
		b.Log("scs nbConstraints", ccs.GetNbConstraints())

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = ccs.IsSolved(witness)
		}
	})

	b.Run("r1cs", func(b *testing.B) {
		var c circuit
		ccs, err := frontend.CompileGeneric[constraint.U64](fr.Modulus(), scs.NewBuilder, &c, frontend.WithCompressThreshold(10))
		if err != nil {
			b.Fatal(err)
		}
		b.Log("r1cs nbConstraints", ccs.GetNbConstraints())

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = ccs.IsSolved(witness)
		}
	})

}
