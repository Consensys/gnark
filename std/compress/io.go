package compress

import (
	"bytes"
	"compress/gzip"
	"github.com/consensys/gnark/frontend"
	"golang.org/x/exp/constraints"
	"io"
	"os"
)

func GzWrite(outFileName string, o io.WriterTo) error {
	var raw bytes.Buffer
	_, err := o.WriteTo(&raw)
	if err != nil {
		return err
	}
	compressed, err := gzCompress(raw.Bytes())
	if err != nil {
		return err
	}
	return os.WriteFile(outFileName, compressed, 0600)
}

func GzRead(inFileName string, o io.ReaderFrom) error {
	compressed, err := os.Open(inFileName)
	if err != nil {
		return err
	}
	reader, err := gzip.NewReader(compressed)
	if err != nil {
		return err
	}

	var decompressed bytes.Buffer
	buff := make([]byte, 1024)
	n, err := reader.Read(buff)
	decompressed.Write(buff[:n])
	for err == nil {
		n, err = reader.Read(buff)
		decompressed.Write(buff[:n])
	}
	if err != io.EOF {
		return err
	}

	if err = compressed.Close(); err != nil {
		return err
	}
	if err = reader.Close(); err != nil {
		return err
	}

	_, err = o.ReadFrom(bytes.NewReader(decompressed.Bytes()))
	return err
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

func Gcd[T constraints.Integer](a ...T) T {
	if len(a) == 0 {
		return 0
	}

	for len(a) > 1 {
		if a[1] < a[0] {
			a[0], a[1] = a[1], a[0]
		}
		for a[0] != 0 {
			a[1], a[0] = a[0], a[1]%a[0]
		}
		a = a[1:]
	}

	return a[0]
}

func Pack(api frontend.API, words []frontend.Variable, wordLen int) []frontend.Variable {
	wordsPerElem := (api.Compiler().FieldBitLen() - 1) / wordLen
	res := make([]frontend.Variable, 1+(len(words)-1)/wordsPerElem)
	for elemI := range res {
		res[elemI] = 0
		for wordI := 0; wordI < wordsPerElem; wordI++ {
			absWordI := elemI*wordsPerElem + wordI
			if absWordI >= len(words) {
				break
			}
			res[elemI] = api.Add(res[elemI], api.Mul(words[absWordI], 1<<uint(wordLen*wordI)))
		}
	}
	return res
}
