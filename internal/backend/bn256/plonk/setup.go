// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plonk

import (
	"github.com/consensys/gnark/crypto/polynomial"
	"github.com/consensys/gnark/crypto/polynomial/bn256"
	"github.com/consensys/gnark/internal/backend/bn256/cs"
	"github.com/consensys/gnark/internal/backend/bn256/fft"
)

// PublicRaw represents the raw public data corresponding to a circuit,
// which consists of the LDE of qr,ql,qm,qo,k of a sparse R1cs. The compact
// version of public data consists of commitments of qr,ql,qm,qo,k.
type PublicRaw struct {

	// Commitment scheme that is used for an instantiation of PLONK
	CommitmentScheme polynomial.CommitmentScheme

	// LDE of qr,ql,qm,qo,k
	Qr, Ql, Qm, Qo, Qk *bn256.Poly

	// Domains used for the FFTs
	DomainNum, DomainH *fft.Domain

	// TODO add the permutation
}

// Setup from a sparseR1CS, it returns the LDE (in
// Lagrange basis) of ql, qr, qm, qo, k.
func Setup(spr *cs.SparseR1CS, polynomialCommitment polynomial.CommitmentScheme) PublicRaw {

	nbConstraints := len(spr.Constraints)
	nbAssertions := len(spr.Assertions)

	var res PublicRaw

	// public polynomials
	for i := 0; i < nbConstraints; i++ {

		res.Ql.Data[i].Set(&spr.Coefficients[spr.Constraints[i].L.CoeffID()])
		res.Qr.Data[i].Set(&spr.Coefficients[spr.Constraints[i].R.CoeffID()])
		res.Qm.Data[i].Set(&spr.Coefficients[spr.Constraints[i].M[0].CoeffID()]).
			Mul(&res.Qm.Data[i], &spr.Coefficients[spr.Constraints[i].M[1].CoeffID()])
		res.Qo.Data[i].Set(&spr.Coefficients[spr.Constraints[i].O.CoeffID()])
		res.Qk.Data[i].Set(&spr.Coefficients[spr.Constraints[i].K])
	}
	for i := 0; i < nbAssertions; i++ {

		index := nbConstraints + i

		res.Ql.Data[index].Set(&spr.Coefficients[spr.Assertions[i].L.CoeffID()])
		res.Qr.Data[index].Set(&spr.Coefficients[spr.Assertions[i].R.CoeffID()])
		res.Qm.Data[index].Set(&spr.Coefficients[spr.Assertions[i].M[0].CoeffID()]).
			Mul(&res.Qm.Data[index], &spr.Coefficients[spr.Assertions[i].M[1].CoeffID()])
		res.Qo.Data[index].Set(&spr.Coefficients[spr.Assertions[i].O.CoeffID()])
		res.Qk.Data[index].Set(&spr.Coefficients[spr.Assertions[i].K])
	}

	// commitment scheme
	res.CommitmentScheme = polynomialCommitment

	// fft domains
	sizeSystem := uint64(nbConstraints + nbAssertions)
	res.DomainNum = fft.NewDomain(sizeSystem, 4)
	res.DomainH = fft.NewDomain(2*sizeSystem, 2)

	return res
}
