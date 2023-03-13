package phase1

import (
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func (c *Contribution) WriteTo(writer io.Writer) (int64, error) {
	toEncode := []interface{}{
		&c.PublicKeys.Tau.SG,
		&c.PublicKeys.Tau.SXG,
		&c.PublicKeys.Tau.XR,
		&c.PublicKeys.Alpha.SG,
		&c.PublicKeys.Alpha.SXG,
		&c.PublicKeys.Alpha.XR,
		&c.PublicKeys.Beta.SG,
		&c.PublicKeys.Beta.SXG,
		&c.PublicKeys.Beta.XR,
		c.Parameters.G1.Tau,
		c.Parameters.G1.AlphaTau,
		c.Parameters.G1.BetaTau,
		c.Parameters.G2.Tau,
		&c.Parameters.G2.Beta,
	}

	enc := bn254.NewEncoder(writer)
	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}
	nBytes, err := writer.Write(c.Hash)
	return int64(nBytes), err
}

func (c *Contribution) ReadFrom(reader io.Reader) (int64, error)   {
	toEncode := []interface{}{
		&c.PublicKeys.Tau.SG,
		&c.PublicKeys.Tau.SXG,
		&c.PublicKeys.Tau.XR,
		&c.PublicKeys.Alpha.SG,
		&c.PublicKeys.Alpha.SXG,
		&c.PublicKeys.Alpha.XR,
		&c.PublicKeys.Beta.SG,
		&c.PublicKeys.Beta.SXG,
		&c.PublicKeys.Beta.XR,
		&c.Parameters.G1.Tau,
		&c.Parameters.G1.AlphaTau,
		&c.Parameters.G1.BetaTau,
		&c.Parameters.G2.Tau,
		&c.Parameters.G2.Beta,
	}

	dec := bn254.NewDecoder(reader)
	for _, v := range toEncode {
		if err := dec.Decode(v); err != nil {
			return dec.BytesRead(), err
		}
	}
	c.Hash = make([]byte, 32)
	nBytes, err := reader.Read(c.Hash)
	return int64(nBytes), err
}
