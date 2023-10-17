package compress

import (
	"bytes"
	"compress/gzip"
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
