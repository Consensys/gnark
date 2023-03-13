package keys

import (
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)
func (pk *ProvingKey) WriteTo(w io.Writer, raw bool) (int64, error) {
	n, err := pk.Domain.WriteTo(w)
	if err != nil {
		return n, err
	}

	var enc *bn254.Encoder
	if raw {
		enc = bn254.NewEncoder(w, bn254.RawEncoding())
	} else {
		enc = bn254.NewEncoder(w)
	}
	nbWires := uint64(len(pk.InfinityA))

	toEncode := []interface{}{
		&pk.G1.Alpha,
		&pk.G1.Beta,
		&pk.G1.Delta,
		pk.G1.A,
		pk.G1.B,
		pk.G1.Z,
		pk.G1.K,
		&pk.G2.Beta,
		&pk.G2.Delta,
		pk.G2.B,
		nbWires,
		pk.NbInfinityA,
		pk.NbInfinityB,
		pk.InfinityA,
		pk.InfinityB,
	}

	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return n + enc.BytesWritten(), err
		}
	}

	return n + enc.BytesWritten(), nil

}

// follows bellman format:
// https://github.com/zkcrypto/bellman/blob/fa9be45588227a8c6ec34957de3f68705f07bd92/src/groth16/mod.rs#L143
// [α]1,[β]1,[β]2,[γ]2,[δ]1,[δ]2,uint32(len(Kvk)),[Kvk]1
func (vk *VerifyingKey) WriteTo(w io.Writer, raw bool) (int64, error) {
	var enc *bn254.Encoder
	if raw {
		enc = bn254.NewEncoder(w, bn254.RawEncoding())
	} else {
		enc = bn254.NewEncoder(w)
	}

	// [α]1,[β]1,[β]2,[γ]2,[δ]1,[δ]2
	if err := enc.Encode(&vk.G1.Alpha); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G1.Beta); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Beta); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Gamma); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G1.Delta); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Delta); err != nil {
		return enc.BytesWritten(), err
	}

	// uint32(len(Kvk)),[Kvk]1
	if err := enc.Encode(vk.G1.K); err != nil {
		return enc.BytesWritten(), err
	}
	return enc.BytesWritten(), nil
}