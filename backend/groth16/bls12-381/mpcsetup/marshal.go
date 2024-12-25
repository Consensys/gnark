// Copyright 2020-2024 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package mpcsetup

import (
	"encoding/binary"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/mpcsetup"
	"github.com/consensys/gnark/internal/utils"
	"io"
)

// WriteTo implements io.WriterTo
// It does not write the Challenge from the previous contribution
func (p *Phase1) WriteTo(writer io.Writer) (n int64, err error) {
	var dn int64
	for _, v := range []io.WriterTo{
		&p.proofs.Tau,
		&p.proofs.Alpha,
		&p.proofs.Beta,
		&p.parameters,
	} {
		dn, err = v.WriteTo(writer)
		n += dn
		if err != nil {
			return
		}
	}
	return
}

// ReadFrom implements io.ReaderFrom
// It does not read the Challenge from the previous contribution
func (p *Phase1) ReadFrom(reader io.Reader) (n int64, err error) {
	var dn int64
	for _, v := range []io.ReaderFrom{
		&p.proofs.Tau,
		&p.proofs.Alpha,
		&p.proofs.Beta,
		&p.parameters,
	} {
		dn, err = v.ReadFrom(reader)
		n += dn
		if err != nil {
			return
		}
	}
	return
}

// slice of references for the parameters of p
func (p *Phase2) refsSlice() []any {
	nbCommitments := len(p.Parameters.G2.Sigma)
	if nbCommitments > 65535 {
		panic("nbCommitments not fitting in 16 bits")
	}

	expectedLen := 2*nbCommitments + 5
	refs := make([]any, 5, expectedLen)
	refs[0] = uint16(nbCommitments)
	refs[1] = &p.Parameters.G1.Delta
	refs[2] = &p.Parameters.G1.PKK // unique size: private input size, excluding those committed to
	refs[3] = &p.Parameters.G1.Z   // unique size: N-1
	refs[4] = &p.Parameters.G2.Delta

	refs = utils.AppendRefs(refs, p.Parameters.G1.SigmaCKK)
	refs = utils.AppendRefs(refs, p.Parameters.G2.Sigma)

	if len(refs) != expectedLen {
		panic("incorrect length estimate")
	}

	return refs
}

// WriteTo implements io.WriterTo
func (p *Phase2) WriteTo(writer io.Writer) (int64, error) {

	// write the parameters
	enc := curve.NewEncoder(writer)
	for _, v := range p.refsSlice() {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}

	//write the proofs
	dn, err := p.Delta.WriteTo(writer)
	n := enc.BytesWritten() + dn
	if err != nil {
		return n, err
	}

	for i := range p.Sigmas {
		dn, err = p.Sigmas[i].WriteTo(writer)
		n += dn
		if err != nil {
			return n, err
		}
	}

	return n, nil
}

// ReadFrom implements io.ReaderFrom
func (p *Phase2) ReadFrom(reader io.Reader) (int64, error) {
	var nbCommitments uint16

	if err := binary.Read(reader, binary.BigEndian, &nbCommitments); err != nil {
		return -1, err // binary.Read doesn't return the number of bytes read
	}
	n := int64(2) // we've definitely successfully read 2 bytes

	p.Sigmas = make([]mpcsetup.UpdateProof, nbCommitments)
	p.Parameters.G1.SigmaCKK = make([][]curve.G1Affine, nbCommitments)
	p.Parameters.G2.Sigma = make([]curve.G2Affine, nbCommitments)

	dec := curve.NewDecoder(reader)
	for _, v := range p.refsSlice()[1:] { // nbCommitments already read
		if err := dec.Decode(v); err != nil {
			return n + dec.BytesRead(), err
		}
	}
	n += dec.BytesRead()

	dn, err := p.Delta.ReadFrom(reader)
	n += dn
	if err != nil {
		return n, err
	}

	for i := range p.Sigmas {
		dn, err = p.Sigmas[i].ReadFrom(reader)
		n += dn
		if err != nil {
			return n, err
		}
	}

	return n, nil
}

func (c *Phase2Evaluations) refsSlice() []any {
	N := uint64(len(c.G1.A))
	expectedLen := 3*N + 3
	refs := make([]any, 3, expectedLen)
	refs[0] = &c.G1.CKK
	refs[1] = &c.G1.VKK
	refs[2] = &c.PublicAndCommitmentCommitted
	refs = utils.AppendRefs(refs, c.G1.A)
	refs = utils.AppendRefs(refs, c.G1.B)
	refs = utils.AppendRefs(refs, c.G2.B)

	if uint64(len(refs)) != expectedLen {
		panic("incorrect length estimate")
	}

	return refs
}

// WriteTo implements io.WriterTo
func (c *Phase2Evaluations) WriteTo(writer io.Writer) (int64, error) {
	enc := curve.NewEncoder(writer)

	for _, v := range c.refsSlice() {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}
	return enc.BytesWritten(), nil
}

// ReadFrom implements io.ReaderFrom
func (c *Phase2Evaluations) ReadFrom(reader io.Reader) (int64, error) {
	var N uint64
	if err := binary.Read(reader, binary.BigEndian, &N); err != nil {
		return -1, err // binary.Read doesn't return the number of bytes read
	}
	n := int64(8)

	c.G1.A = make([]curve.G1Affine, N)
	c.G1.B = make([]curve.G1Affine, N)
	c.G2.B = make([]curve.G2Affine, N)

	dec := curve.NewDecoder(reader)
	for _, v := range c.refsSlice()[1:] {
		if err := dec.Decode(v); err != nil {
			return n + dec.BytesRead(), err
		}
	}

	return n + dec.BytesRead(), nil
}

// refsSlice produces a slice consisting of references to all sub-elements
// prepended by the size parameter, to be used in WriteTo and ReadFrom functions
func (c *SrsCommons) refsSlice() []any {
	N := uint64(len(c.G2.Tau))
	expectedLen := 5*N - 1
	// size N                                                                    1
	// [β]₂                                                                      1
	// [τⁱ]₁  for 1 ≤ i ≤ 2N-2                                                2N-2
	// [τⁱ]₂  for 1 ≤ i ≤ N-1                                                  N-1
	// [ατⁱ]₁ for 0 ≤ i ≤ N-1                                                  N
	// [βτⁱ]₁ for 0 ≤ i ≤ N-1                                                  N
	refs := make([]any, 2, expectedLen)
	refs[0] = N
	refs[1] = &c.G2.Beta
	refs = utils.AppendRefs(refs, c.G1.Tau[1:])
	refs = utils.AppendRefs(refs, c.G2.Tau[1:])
	refs = utils.AppendRefs(refs, c.G1.BetaTau)
	refs = utils.AppendRefs(refs, c.G1.AlphaTau)

	if uint64(len(refs)) != expectedLen {
		panic("incorrect length estimate")
	}

	return refs
}

func (c *SrsCommons) WriteTo(writer io.Writer) (int64, error) {
	enc := curve.NewEncoder(writer)
	for _, v := range c.refsSlice() {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}
	return enc.BytesWritten(), nil
}

// ReadFrom implements io.ReaderFrom
func (c *SrsCommons) ReadFrom(reader io.Reader) (n int64, err error) {
	var N uint64
	dec := curve.NewDecoder(reader)
	if err = dec.Decode(&N); err != nil {
		return dec.BytesRead(), err
	}

	c.setZero(N)

	for _, v := range c.refsSlice()[1:] { // we've already decoded N
		if err = dec.Decode(v); err != nil {
			return dec.BytesRead(), err
		}
	}
	return dec.BytesRead(), nil
}
