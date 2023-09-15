package lzss_v1

import (
	"bytes"
	"compress/gzip"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"os"
)

type DecompressionTestCircuit struct {
	C        []frontend.Variable
	D        []byte
	Settings Settings
}

func (c *DecompressionTestCircuit) Define(api frontend.API) error {
	dBack := make([]frontend.Variable, len(c.D)*2) // TODO Try smaller constants
	api.Println("maxLen(dBack)", len(dBack))
	dLen, err := Decompress(api, c.C, dBack, c.Settings)
	if err != nil {
		return err
	}
	api.Println("got len", dLen, "expected", len(c.D))
	api.AssertIsEqual(len(c.D), dLen)
	for i := range c.D {
		api.Println("decompressed at", i, "->", dBack[i], "expected", c.D[i], "dBack", dBack[i])
		api.AssertIsEqual(c.D[i], dBack[i])
	}
	return nil
}

func GzCompressCs(outFileName string, cs constraint.ConstraintSystem) error {
	var raw bytes.Buffer
	_, err := cs.WriteTo(&raw)
	if err != nil {
		return err
	}
	compressed, err := gzCompress(raw.Bytes())
	if err != nil {
		return err
	}
	return os.WriteFile(outFileName, compressed, 0644)
}

func gzCompress(in []byte) ([]byte, error) {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	_, err := w.Write(in)
	if err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
