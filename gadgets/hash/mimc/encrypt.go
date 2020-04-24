/*
Copyright © 2020 ConsenSys

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

package mimc

import (
	"math/big"

	"github.com/consensys/gnark/crypto/hash/mimc/bls377"
	"github.com/consensys/gnark/crypto/hash/mimc/bls381"
	"github.com/consensys/gnark/crypto/hash/mimc/bn256"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

var encryptFuncs map[gurvy.ID]func(*frontend.CS, MiMCGadget, *frontend.Constraint, *frontend.Constraint) *frontend.Constraint
var newMimc map[gurvy.ID]func(string) MiMCGadget

func init() {
	encryptFuncs = make(map[gurvy.ID]func(*frontend.CS, MiMCGadget, *frontend.Constraint, *frontend.Constraint) *frontend.Constraint)
	encryptFuncs[gurvy.BN256] = encryptBN256
	encryptFuncs[gurvy.BLS381] = encryptBLS381
	encryptFuncs[gurvy.BLS377] = encryptBLS377

	newMimc = make(map[gurvy.ID]func(string) MiMCGadget)
	newMimc[gurvy.BN256] = newMimcBN256
	newMimc[gurvy.BLS381] = newMimcBLS381
	newMimc[gurvy.BLS377] = newMimcBLS377
}

// -------------------------------------------------------------------------------------------------
// constructors

func newMimcBLS377(seed string) MiMCGadget {
	res := MiMCGadget{}
	params := bls377.NewParams(seed)
	for _, v := range params {
		var cpy big.Int
		v.ToBigIntRegular(&cpy)
		res.Params = append(res.Params, cpy)
	}
	res.id = gurvy.BLS377
	return res
}

func newMimcBLS381(seed string) MiMCGadget {
	res := MiMCGadget{}
	params := bls381.NewParams(seed)
	for _, v := range params {
		var cpy big.Int
		v.ToBigIntRegular(&cpy)
		res.Params = append(res.Params, cpy)
	}
	res.id = gurvy.BLS381
	return res
}

func newMimcBN256(seed string) MiMCGadget {
	res := MiMCGadget{}
	params := bn256.NewParams(seed)
	for _, v := range params {
		var cpy big.Int
		v.ToBigIntRegular(&cpy)
		res.Params = append(res.Params, cpy)
	}
	res.id = gurvy.BN256
	return res
}

// -------------------------------------------------------------------------------------------------
// encryptions functions

// encryptBn256 of a mimc run expressed as r1cs
func encryptBN256(circuit *frontend.CS, h MiMCGadget, message, key *frontend.Constraint) *frontend.Constraint {

	res := message

	for i := 0; i < len(h.Params); i++ {
		//for i := 0; i < 1; i++ {
		tmp := circuit.ADD(res, key, h.Params[i])
		// res = (res+k+c)^7
		res = circuit.MUL(tmp, tmp)
		res = circuit.MUL(res, tmp)
		res = circuit.MUL(res, res)
		res = circuit.MUL(res, tmp)
	}
	res = circuit.ADD(res, key)
	return res

}

// execution of a mimc run expressed as r1cs
func encryptBLS381(circuit *frontend.CS, h MiMCGadget, message *frontend.Constraint, key *frontend.Constraint) *frontend.Constraint {

	res := message

	for i := 0; i < len(h.Params); i++ {
		tmp := circuit.ADD(res, key, h.Params[i])
		// res = (res+k+c)^5
		res = circuit.MUL(tmp, tmp) // square
		res = circuit.MUL(res, res) // square
		res = circuit.MUL(res, tmp) // mul
	}
	res = circuit.ADD(res, key)
	return res

}

// encryptBLS377 of a mimc run expressed as r1cs
func encryptBLS377(circuit *frontend.CS, h MiMCGadget, message *frontend.Constraint, key *frontend.Constraint) *frontend.Constraint {
	res := message
	for i := 0; i < len(h.Params); i++ {
		tmp := circuit.ADD(res, h.Params[i], key)
		// res = (res+key+c)**-1
		res = circuit.INV(tmp)
	}
	res = circuit.ADD(res, key)
	return res

}
