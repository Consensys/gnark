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

var encryptFuncs map[gurvy.ID]func(*frontend.CS, MiMC, frontend.Variable, frontend.Variable) frontend.Variable
var newMimc map[gurvy.ID]func(string) MiMC

func init() {
	encryptFuncs = make(map[gurvy.ID]func(*frontend.CS, MiMC, frontend.Variable, frontend.Variable) frontend.Variable)
	encryptFuncs[gurvy.BN256] = encryptBN256
	encryptFuncs[gurvy.BLS381] = encryptBLS381
	encryptFuncs[gurvy.BLS377] = encryptBLS377

	newMimc = make(map[gurvy.ID]func(string) MiMC)
	newMimc[gurvy.BN256] = newMimcBN256
	newMimc[gurvy.BLS381] = newMimcBLS381
	newMimc[gurvy.BLS377] = newMimcBLS377
}

// -------------------------------------------------------------------------------------------------
// constructors

func newMimcBLS377(seed string) MiMC {
	res := MiMC{}
	params := bls377.NewParams(seed)
	for _, v := range params {
		var cpy big.Int
		v.ToBigIntRegular(&cpy)
		res.params = append(res.params, cpy)
	}
	res.id = gurvy.BLS377
	return res
}

func newMimcBLS381(seed string) MiMC {
	res := MiMC{}
	params := bls381.NewParams(seed)
	for _, v := range params {
		var cpy big.Int
		v.ToBigIntRegular(&cpy)
		res.params = append(res.params, cpy)
	}
	res.id = gurvy.BLS381
	return res
}

func newMimcBN256(seed string) MiMC {
	res := MiMC{}
	params := bn256.NewParams(seed)
	for _, v := range params {
		var cpy big.Int
		v.ToBigIntRegular(&cpy)
		res.params = append(res.params, cpy)
	}
	res.id = gurvy.BN256
	return res
}

// -------------------------------------------------------------------------------------------------
// encryptions functions

// encryptBn256 of a mimc run expressed as r1cs
func encryptBN256(cs *frontend.CS, h MiMC, message, key frontend.Variable) frontend.Variable {

	res := message

	for i := 0; i < len(h.params); i++ {
		//for i := 0; i < 1; i++ {
		tmp := cs.Add(res, key, h.params[i])
		// res = (res+k+c)^7
		res = cs.Mul(tmp, tmp)
		res = cs.Mul(res, tmp)
		res = cs.Mul(res, res)
		res = cs.Mul(res, tmp)
	}
	res = cs.Add(res, key)
	return res

}

// execution of a mimc run expressed as r1cs
func encryptBLS381(cs *frontend.CS, h MiMC, message frontend.Variable, key frontend.Variable) frontend.Variable {

	res := message

	for i := 0; i < len(h.params); i++ {
		tmp := cs.Add(res, key, h.params[i])
		// res = (res+k+c)^5
		res = cs.Mul(tmp, tmp) // square
		res = cs.Mul(res, res) // square
		res = cs.Mul(res, tmp) // mul
	}
	res = cs.Add(res, key)
	return res

}

// encryptBLS377 of a mimc run expressed as r1cs
func encryptBLS377(cs *frontend.CS, h MiMC, message frontend.Variable, key frontend.Variable) frontend.Variable {
	res := message
	for i := 0; i < len(h.params); i++ {
		tmp := cs.Add(res, h.params[i], key)
		// res = (res+key+c)**-1
		res = cs.Inverse(tmp)
	}
	res = cs.Add(res, key)
	return res

}
