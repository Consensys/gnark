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

package mockcommitment

import (
	"io"

	"github.com/consensys/gnark/crypto/polynomial/bn256"
	"github.com/consensys/gurvy/bn256/fr"
)

// MockDigest contains the polynomial itself
type MockDigest struct {
	Digest []fr.Element
}

// WriteTo mock impementation
func (md *MockDigest) WriteTo(w io.Writer) (n int64, err error) {
	return 0, nil
}

// ReadFrom mock impementation
func (md *MockDigest) ReadFrom(r io.Reader) (n int64, err error) {
	return 0, nil
}

// MockProof empty struct
type MockProof struct {
	ClaimedEvaluation fr.Element
}

// WriteTo mock impementation
func (mp *MockProof) WriteTo(w io.Writer) (n int64, err error) {
	return 0, nil
}

// ReadFrom mock impementation
func (mp *MockProof) ReadFrom(r io.Reader) (n int64, err error) {
	return 0, nil
}

// ClaimedValue returns the claimed value from the proof
func (mp *MockProof) ClaimedValue() fr.Element {
	return mp.ClaimedEvaluation
}

// MockCommitmentScheme mock commitment, useful for testing polynomial based IOP
// like PLONK, where the scheme should not depend on which polynomial commitment scheme
// is used.
type MockCommitmentScheme struct{}

// WriteTo panics
func (mcs *MockCommitmentScheme) WriteTo(w io.Writer) (n int64, err error) {
	return 0, nil
}

// ReadFrom panics
func (mcs *MockCommitmentScheme) ReadFrom(r io.Reader) (n int64, err error) {
	return 0, nil
}

// Commit returns nil
func (mcs *MockCommitmentScheme) Commit(p *bn256.Poly) *MockDigest {
	res := &MockDigest{Digest: p.Data}
	return res
}

// Open computes the evaluation of p at val, the proof is nil.
// The opening value is the plain polynomial evaluation at val (in
// particular it assumes that the polynomial is representated using
// the canonical basis, where p.Data[0] the degree 0 coefficient,
// p.Data[len(p.Data)-1] is the highest coefficient).
func (mcs *MockCommitmentScheme) Open(p *bn256.Poly, val *fr.Element) *MockProof {
	var res MockProof
	for i := len(p.Data) - 1; i >= 0; i-- {
		res.ClaimedEvaluation.Add(&res.ClaimedEvaluation, &p.Data[i])
		res.ClaimedEvaluation.Mul(&res.ClaimedEvaluation, val)
	}
	return &res
}

// Verify mock implementation of verify
func (mcs *MockCommitmentScheme) Verify(d *MockDigest, p *MockProof, v *fr.Element) bool {
	return true
}
