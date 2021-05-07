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

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/mimc"

	"github.com/consensys/gnark/frontend"
)

var encryptFuncs map[ecc.ID]func(*frontend.ConstraintSystem, MiMC, frontend.Variable, frontend.Variable) frontend.Variable
var newMimc map[ecc.ID]func(string) MiMC

func init() {
	encryptFuncs = make(map[ecc.ID]func(*frontend.ConstraintSystem, MiMC, frontend.Variable, frontend.Variable) frontend.Variable)
	encryptFuncs[ecc.BN254] = encryptBN254
	encryptFuncs[ecc.BLS12_381] = encryptBLS381
	encryptFuncs[ecc.BLS12_377] = encryptBLS377
	encryptFuncs[ecc.BW6_761] = encryptBW761
	encryptFuncs[ecc.BLS24_315] = encryptBLS315

	newMimc = make(map[ecc.ID]func(string) MiMC)
	newMimc[ecc.BN254] = newMimcBN254
	newMimc[ecc.BLS12_381] = newMimcBLS381
	newMimc[ecc.BLS12_377] = newMimcBLS377
	newMimc[ecc.BW6_761] = newMimcBW761
	newMimc[ecc.BLS24_315] = newMimcBLS315
}

// -------------------------------------------------------------------------------------------------
// constructors

func newMimcBLS377(seed string) MiMC {
	res := MiMC{}
	params := bls12377.NewParams(seed)
	for _, v := range params {
		var cpy big.Int
		v.ToBigIntRegular(&cpy)
		res.params = append(res.params, cpy)
	}
	res.id = ecc.BLS12_377
	return res
}

func newMimcBLS381(seed string) MiMC {
	res := MiMC{}
	params := bls12381.NewParams(seed)
	for _, v := range params {
		var cpy big.Int
		v.ToBigIntRegular(&cpy)
		res.params = append(res.params, cpy)
	}
	res.id = ecc.BLS12_381
	return res
}

func newMimcBN254(seed string) MiMC {
	res := MiMC{}
	params := bn254.NewParams(seed)
	for _, v := range params {
		var cpy big.Int
		v.ToBigIntRegular(&cpy)
		res.params = append(res.params, cpy)
	}
	res.id = ecc.BN254
	return res
}

func newMimcBW761(seed string) MiMC {
	res := MiMC{}
	params := bw6761.NewParams(seed)
	for _, v := range params {
		var cpy big.Int
		v.ToBigIntRegular(&cpy)
		res.params = append(res.params, cpy)
	}
	res.id = ecc.BW6_761
	return res
}

func newMimcBLS315(seed string) MiMC {
	res := MiMC{}
	params := bls24315.NewParams(seed)
	for _, v := range params {
		var cpy big.Int
		v.ToBigIntRegular(&cpy)
		res.params = append(res.params, cpy)
	}
	res.id = ecc.BLS24_315
	return res
}
// -------------------------------------------------------------------------------------------------
// encryptions functions

// encryptBn256 of a mimc run expressed as r1cs
func encryptBN254(cs *frontend.ConstraintSystem, h MiMC, message, key frontend.Variable) frontend.Variable {

	res := message
	// one := big.NewInt(1)
	for i := 0; i < len(h.params); i++ {
		tmp := cs.Add(res, key, h.params[i])
		// res = (res+k+c)^5
		res = cs.Mul(tmp, tmp)
		res = cs.Mul(res, res)
		res = cs.Mul(res, tmp)
	}
	res = cs.Add(res, key)
	return res

}

// execution of a mimc run expressed as r1cs
func encryptBLS381(cs *frontend.ConstraintSystem, h MiMC, message frontend.Variable, key frontend.Variable) frontend.Variable {

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

// execution of a mimc run expressed as r1cs
func encryptBW761(cs *frontend.ConstraintSystem, h MiMC, message frontend.Variable, key frontend.Variable) frontend.Variable {

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
func encryptBLS377(cs *frontend.ConstraintSystem, h MiMC, message frontend.Variable, key frontend.Variable) frontend.Variable {
	res := message
	for i := 0; i < len(h.params); i++ {
		tmp := cs.Add(res, h.params[i], key)
		// res = (res+key+c)**-1
		res = cs.Inverse(tmp)
	}
	res = cs.Add(res, key)
	return res

}

// encryptBLS315 of a mimc run expressed as r1cs
func encryptBLS315(cs *frontend.ConstraintSystem, h MiMC, message frontend.Variable, key frontend.Variable) frontend.Variable {
	res := message
	for i := 0; i < len(h.params); i++ {
		tmp := cs.Add(res, h.params[i], key)
		// res = (res+k+c)^5
		res = cs.Mul(tmp, tmp) // square
		res = cs.Mul(res, res) // square
		res = cs.Mul(res, tmp) // mul
	}
	res = cs.Add(res, key)
	return res

}
