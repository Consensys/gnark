package phase2

import (
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func (c *Contribution) WriteTo(writer io.Writer) (int64, error) {
	enc := bn254.NewEncoder(writer)
	toEncode := []interface{}{
		&c.PublicKey.SG,
		&c.PublicKey.SXG,
		&c.PublicKey.XR,
		&c.Parameters.G1.Delta,
		c.Parameters.G1.L,
		c.Parameters.G1.Z,
		&c.Parameters.G2.Delta,
	}

	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}

	n, err := writer.Write(c.Hash)
	return int64(n), err

}
func (c *Contribution) ReadFrom(reader io.Reader) (int64, error) {
	dec := bn254.NewDecoder(reader)
	toEncode := []interface{}{
		&c.PublicKey.SG,
		&c.PublicKey.SXG,
		&c.PublicKey.XR,
		&c.Parameters.G1.Delta,
		&c.Parameters.G1.L,
		&c.Parameters.G1.Z,
		&c.Parameters.G2.Delta,
	}

	for _, v := range toEncode {
		if err := dec.Decode(v); err != nil {
			return dec.BytesRead(), err
		}
	}

	c.Hash = make([]byte, 32)
	n, err := reader.Read(c.Hash)
	return int64(n), err

}

func (c *Evaluations) WriteTo(writer io.Writer) (int64, error) {
	enc := bn254.NewEncoder(writer)
	toEncode := []interface{}{
		c.G1.A,
		c.G1.B,
		c.G2.B,
	}

	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}

	return enc.BytesWritten(), nil
}

func (c *Evaluations) ReadFrom(reader io.Reader) (int64, error) {
	dec := bn254.NewDecoder(reader)
	toEncode := []interface{}{
		&c.G1.A,
		&c.G1.B,
		&c.G2.B,
	}

	for _, v := range toEncode {
		if err := dec.Decode(v); err != nil {
			return dec.BytesRead(), err
		}
	}

	return dec.BytesRead(), nil
}
