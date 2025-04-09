// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package mpcsetup

import (
	"encoding/binary"
	"io"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/mpcsetup"
	gIo "github.com/consensys/gnark/io"
)

// UnsafeReadFrom implements io.UnsafeReaderFrom
func (p *Phase2) UnsafeReadFrom(reader io.Reader) (n int64, err error) {
	var nbCommitments uint16

	if err = binary.Read(reader, binary.BigEndian, &nbCommitments); err != nil {
		return -1, err
	}
	n = 2

	p.Sigmas = make([]mpcsetup.UpdateProof, nbCommitments)
	p.Parameters.G1.SigmaCKK = make([][]curve.G1Affine, nbCommitments)
	p.Parameters.G2.Sigma = make([]curve.G2Affine, nbCommitments)

	dec := curve.NewDecoder(reader)
	for _, v := range p.refsSlice() {
		if err = dec.Decode(v); err != nil {
			return n + dec.BytesRead(), err
		}
	}

	if err = dec.Decode(&p.Delta); err != nil {
		return n + dec.BytesRead(), err
	}

	for i := range p.Sigmas {
		if err = dec.Decode(&p.Sigmas[i]); err != nil {
			return n + dec.BytesRead(), err
		}
	}

	challenge, dn, err := gIo.ReadBytesShort(reader)
	if err != nil {
		return n + dec.BytesRead() + dn, err
	}
	p.Challenge = challenge
	return n + dec.BytesRead() + dn, nil
}

// BinaryDump implements io.BinaryDumper
func (p *Phase2) BinaryDump(writer io.Writer) (n int64, err error) {
	if err = binary.Write(writer, binary.BigEndian, uint16(len(p.Parameters.G2.Sigma))); err != nil {
		return -1, err
	}
	n = 2

	enc := curve.NewEncoder(writer)
	for _, v := range p.refsSlice() {
		if err = enc.Encode(v); err != nil {
			return n + enc.BytesWritten(), err
		}
	}

	if err = enc.Encode(&p.Delta); err != nil {
		return n + enc.BytesWritten(), err
	}

	for i := range p.Sigmas {
		if err = enc.Encode(&p.Sigmas[i]); err != nil {
			return n + enc.BytesWritten(), err
		}
	}

	dn, err := gIo.WriteBytesShort(p.Challenge, writer)
	if err != nil {
		return n + enc.BytesWritten() + dn, err
	}
	return n + enc.BytesWritten() + dn, nil
}
