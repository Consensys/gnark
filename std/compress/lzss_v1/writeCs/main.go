package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/compress/lzss_v1"
	"os"
)

// executable to generate the constraints for the circuit and store it

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	c := lzss_v1.DecompressionTestCircuit{
		C: make([]frontend.Variable, 120000),
		D: make([]byte, 612000),
		Settings: lzss_v1.Settings{
			BackRefSettings: lzss_v1.BackRefSettings{
				NbBytesAddress: 2,
				NbBytesLength:  1,
				Symbol:         0,
			},
		},
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &c)
	check(err)

	fmt.Println(cs.GetNbConstraints(), "constraints")
	check(gzCompressCs("600kb.gz", cs))
}

func gzCompressCs(outFileName string, cs constraint.ConstraintSystem) error {
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
