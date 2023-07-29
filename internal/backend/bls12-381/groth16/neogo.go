package groth16

// neoGoTemplate is a Verifier smart contract template written in Go for Neo blockchain.
// It contains a single `verifyProof` method that accepts a proof represented as three
// BLS12-381 curve points and public witnesses required for verification
// represented as a list of serialized 32-bytes field elements in the LE form.
// The boolean result of `verifyProof` is either `true` (if the proof is
// valid) or `false` (if the proof is invalid). The smart contract generated
// from this template can be immediately compiled without any additional
// changes using NeoGo compiler, deployed to the Neo chain and invoked. The
// verification contract is circuit-specific, i.e. corresponds to a specific
// single constraint system. Thus, every new circuit requires vew verification
// contract to be generated and deployed to the chain.
//
// The contract template was not audited and is delivered "As Is" by the NeoGo developers.
// Contract template source: https://github.com/nspcc-dev/neo-go/pull/3043 // TODO
//
// This is an experimental feature and gnark NeoGo generator as not been thoroughly tested.
const neoGoTemplate = `// Package main contains verification smart contract that uses Neo BLS12-381
// curves interoperability functionality to verify provided proof against provided
// public witnesses using Groth-16 verification system. The contract contains a
// single 'verifyProof'' method that accepts a proof represented as three BLS12-381
// curve points and public witnesses required for verification represented as a
// list of serialized 32-bytes field elements in the LE form. This contract is
// circuit-specific and can not be used to verify other circuits.
//
// Use NeoGo smart contract compiler to compile this contract:
// https://github.com/nspcc-dev/neo-go. You will need to create contract configuration
// file and proper go.mod and go.sum files required for compilation. Please, refer
// to the NeoGo ZKP example to see how to verify proves using this contract.
package main

import (
	"github.com/nspcc-dev/neo-go/pkg/interop/native/crypto"
	"github.com/nspcc-dev/neo-go/pkg/interop/util"
)

// A set of circuit-specific variables required for verification. Should be generated
// using MPC process.
var (
	// G1 Affine point.
	alpha = []byte{{ byteSliceToStr .G1.Alpha.Bytes }}
	// G2 Affine point.
	beta = []byte{{ byteSliceToStr .G2.Beta.Bytes }}
	// G2 Affine point.
	gamma = []byte{{ byteSliceToStr .G2.Gamma.Bytes }}
	// G2 Affine point.
	delta = []byte{{ byteSliceToStr .G2.Delta.Bytes }}
	// A set of G1 Affine points.
	ic = [][]byte{
		{{- range $i := .G1.K }}
		{{ byteSliceToStr $i.Bytes }},{{ end -}}
	}
)

// VerifyProof verifies the given proof represented as three serialized compressed
// BLS12-381 points against the public information represented as a list of
// serialized 32-bytes field elements in the LE form. Verification process
// follows the Groth-16 proving system and is taken from the
// https://github.com/neo-project/neo/issues/2647#issuecomment-1002893109 without
// any changes. Verification process checks the following equality:
// A*B = alpha*beta + sum(pub_input[i]*(beta*u_i(x)+alpha*v_i(x)+w_i(x))/gamma)*gamma + C*delta
func VerifyProof(a []byte, b []byte, c []byte, publicInput [][]byte) bool {
	alphaPoint := crypto.Bls12381Deserialize(alpha)
	betaPoint := crypto.Bls12381Deserialize(beta)
	gammaPoint := crypto.Bls12381Deserialize(gamma)
	deltaPoint := crypto.Bls12381Deserialize(delta)

	aPoint := crypto.Bls12381Deserialize(a)
	bPoint := crypto.Bls12381Deserialize(b)
	cPoint := crypto.Bls12381Deserialize(c)

	// Equation left1: A*B
	lt := crypto.Bls12381Pairing(aPoint, bPoint)

	// Equation right1: alpha*beta
	rt1 := crypto.Bls12381Pairing(alphaPoint, betaPoint)

	// Equation right2: sum(pub_input[i]*(beta*u_i(x)+alpha*v_i(x)+w_i(x))/gamma)*gamma
	inputlen := len(publicInput)
	iclen := len(ic)

	if iclen != inputlen+1 {
		panic("error: inputlen or iclen")
	}
	icPoints := make([]crypto.Bls12381Point, iclen)
	for i := 0; i < iclen; i++ {
		icPoints[i] = crypto.Bls12381Deserialize(ic[i])
	}
	acc := icPoints[0]
	for i := 0; i < inputlen; i++ {
		scalar := publicInput[i] // 32-bytes LE field element.
		temp := crypto.Bls12381Mul(icPoints[i+1], scalar, false)
		acc = crypto.Bls12381Add(acc, temp)
	}
	rt2 := crypto.Bls12381Pairing(acc, gammaPoint)

	// Equation right3: C*delta
	rt3 := crypto.Bls12381Pairing(cPoint, deltaPoint)

	// Check equality.
	t1 := crypto.Bls12381Add(rt1, rt2)
	t2 := crypto.Bls12381Add(t1, rt3)

	return util.Equals(lt, t2)
}
`
