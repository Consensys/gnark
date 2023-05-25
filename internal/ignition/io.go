package ignition

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

// readOrDownload reads a file from disk if it exists, or downloads it from the URL if it doesn't.
// It returns the file contents as a byte slice.
// It also saves the file to disk if it was downloaded.
func readOrDownload(baseURL, file string, config Config) ([]byte, error) {

	if config.CacheDir != "" && fileExists(filepath.Join(config.cache(), file)) {
		// reading from cache
		file = filepath.Join(config.cache(), file)
		log.Println("read", file)
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(f)
	}

	var buf bytes.Buffer
	baseURL, err := url.JoinPath(baseURL, file)
	if err != nil {
		return nil, err
	}
	log.Println("download", baseURL, file)
	// Send HTTP GET request to the URL
	// --> Potential HTTP request made with variable url
	// this is for illustrative purposes only.
	response, err := http.Get(baseURL) //#nosec G107
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var writer io.Writer
	writer = &buf

	// create the file
	if config.CacheDir != "" {
		file = filepath.Join(config.cache(), file)
		dir := filepath.Dir(file)
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return nil, err
		}
		f, err := os.Create(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		writer = io.MultiWriter(f, writer)
	}

	_, err = io.Copy(writer, response.Body)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil

}

func readG1Points(b []byte, nbPoints uint32, r []bn254.G1Affine) {
	// per the specs:
	// For big-integer numbers (g1, g2 coordinates),
	// we describe each 256-bit field element as a uint64_t[4] array.
	// The first entry is the least significant word of the field element. Each 'word' is written in big-endian form.
	offset := 0
	for i := 0; i < int(nbPoints); i++ {
		// TODO we could parallelize that
		data := b[offset : offset+fp.Bytes*2]

		r[i].X[0] = binary.BigEndian.Uint64(data[0:8])
		r[i].X[1] = binary.BigEndian.Uint64(data[8:16])
		r[i].X[2] = binary.BigEndian.Uint64(data[16:24])
		r[i].X[3] = binary.BigEndian.Uint64(data[24:32])
		// p.X.Mul(&p.X, &rSquare) // to montgomery form

		r[i].Y[0] = binary.BigEndian.Uint64(data[32:40])
		r[i].Y[1] = binary.BigEndian.Uint64(data[40:48])
		r[i].Y[2] = binary.BigEndian.Uint64(data[48:56])
		r[i].Y[3] = binary.BigEndian.Uint64(data[56:64])
		// p.Y.Mul(&p.Y, &rSquare) // to montgomery form

		offset += fp.Bytes * 2
	}
}

func readG2Points(data []byte, r *[2]bn254.G2Affine) {
	_ = data[255]
	// per the specs:
	// For big-integer numbers (g1, g2 coordinates),
	// we describe each 256-bit field element as a uint64_t[4] array.
	// The first entry is the least significant word of the field element. Each 'word' is written in big-endian form.

	r[0].X.A0[0] = binary.BigEndian.Uint64(data[0:8])
	r[0].X.A0[1] = binary.BigEndian.Uint64(data[8:16])
	r[0].X.A0[2] = binary.BigEndian.Uint64(data[16:24])
	r[0].X.A0[3] = binary.BigEndian.Uint64(data[24:32])
	r[0].X.A0.Mul(&r[0].X.A0, &rSquare) // to montgomery form

	r[0].X.A1[0] = binary.BigEndian.Uint64(data[32:40])
	r[0].X.A1[1] = binary.BigEndian.Uint64(data[40:48])
	r[0].X.A1[2] = binary.BigEndian.Uint64(data[48:56])
	r[0].X.A1[3] = binary.BigEndian.Uint64(data[56:64])
	r[0].X.A1.Mul(&r[0].X.A1, &rSquare) // to montgomery form

	r[0].Y.A0[0] = binary.BigEndian.Uint64(data[64:72])
	r[0].Y.A0[1] = binary.BigEndian.Uint64(data[72:80])
	r[0].Y.A0[2] = binary.BigEndian.Uint64(data[80:88])
	r[0].Y.A0[3] = binary.BigEndian.Uint64(data[88:96])
	r[0].Y.A0.Mul(&r[0].Y.A0, &rSquare) // to montgomery form

	r[0].Y.A1[0] = binary.BigEndian.Uint64(data[96:104])
	r[0].Y.A1[1] = binary.BigEndian.Uint64(data[104:112])
	r[0].Y.A1[2] = binary.BigEndian.Uint64(data[112:120])
	r[0].Y.A1[3] = binary.BigEndian.Uint64(data[120:128])
	r[0].Y.A1.Mul(&r[0].Y.A1, &rSquare) // to montgomery form

	r[1].X.A0[0] = binary.BigEndian.Uint64(data[128:136])
	r[1].X.A0[1] = binary.BigEndian.Uint64(data[136:144])
	r[1].X.A0[2] = binary.BigEndian.Uint64(data[144:152])
	r[1].X.A0[3] = binary.BigEndian.Uint64(data[152:160])
	r[1].X.A0.Mul(&r[1].X.A0, &rSquare) // to montgomery form

	r[1].X.A1[0] = binary.BigEndian.Uint64(data[160:168])
	r[1].X.A1[1] = binary.BigEndian.Uint64(data[168:176])
	r[1].X.A1[2] = binary.BigEndian.Uint64(data[176:184])
	r[1].X.A1[3] = binary.BigEndian.Uint64(data[184:192])
	r[1].X.A1.Mul(&r[1].X.A1, &rSquare) // to montgomery form

	r[1].Y.A0[0] = binary.BigEndian.Uint64(data[192:200])
	r[1].Y.A0[1] = binary.BigEndian.Uint64(data[200:208])
	r[1].Y.A0[2] = binary.BigEndian.Uint64(data[208:216])
	r[1].Y.A0[3] = binary.BigEndian.Uint64(data[216:224])
	r[1].Y.A0.Mul(&r[1].Y.A0, &rSquare) // to montgomery form

	r[1].Y.A1[0] = binary.BigEndian.Uint64(data[224:232])
	r[1].Y.A1[1] = binary.BigEndian.Uint64(data[232:240])
	r[1].Y.A1[2] = binary.BigEndian.Uint64(data[240:248])
	r[1].Y.A1[3] = binary.BigEndian.Uint64(data[248:256])
	r[1].Y.A1.Mul(&r[1].Y.A1, &rSquare) // to montgomery form

}

// rSquare montgomery constant
var rSquare = fp.Element{
	17522657719365597833,
	13107472804851548667,
	5164255478447964150,
	493319470278259999,
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}
