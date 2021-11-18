/*
Copyright © 2021 ConsenSys Software Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package frontend

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
)

func TestPrintln(t *testing.T) {
	// must not panic.
	cs := newConstraintSystem(ecc.BN254)
	one := cs.newPublicVariable("one")

	cs.Println(nil)
	cs.Println(1)
	cs.Println("a")
	cs.Println(new(big.Int).SetInt64(2))
	cs.Println(one)

	cs.Println(nil, 1, "a", new(big.Int), one)
}

// empty circuits
type IsBool1 struct{}
type IsBool2 struct{}
type IsBool3 struct{}

func TestIsBool1(t *testing.T) {

	var circuit IsBool1

	_, err := Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal("compilation failed", err)
	}
}

func TestIsBool2(t *testing.T) {

	var circuit IsBool2

	_, err := Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal("compilation failed", err)
	}
}

func TestIsBool3(t *testing.T) {

	var circuit IsBool3

	_, err := Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal("compilation failed", err)
	}
}

func (c *IsBool1) Define(cs API) error {

	cs.AssertIsBoolean(0)
	cs.AssertIsBoolean(1)
	return nil
}

func (c *IsBool2) Define(cs API) error {

	sum := cs.Add(0, 1)
	cs.AssertIsBoolean(sum)
	return nil
}

func (c *IsBool3) Define(cs API) error {

	prod := cs.Mul(0, 1)
	cs.AssertIsBoolean(prod)

	return nil
}
