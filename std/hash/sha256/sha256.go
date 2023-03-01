package sha256

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

const chunk = 64

var (
	h0 = keccakf.ConstUint32(0x6A09E667)
	h1 = keccakf.ConstUint32(0xBB67AE85)
	h2 = keccakf.ConstUint32(0x3C6EF372)
	h3 = keccakf.ConstUint32(0xA54FF53A)
	h4 = keccakf.ConstUint32(0x510E527F)
	h5 = keccakf.ConstUint32(0x9B05688C)
	h6 = keccakf.ConstUint32(0x1F83D9AB)
	h7 = keccakf.ConstUint32(0x5BE0CD19)
)

type Digest struct {
	h   [8]keccakf.Xuint32
	x   [chunk]keccakf.Xuint8 // 64 byte
	nx  int
	len uint64
	id  ecc.ID
	api frontend.API
}

func (d *Digest) Reset() {
	d.h[0] = h0
	d.h[1] = h1
	d.h[2] = h2
	d.h[3] = h3
	d.h[4] = h4
	d.h[5] = h5
	d.h[6] = h6
	d.h[7] = h7

	d.nx = 0
	d.len = 0
}

func Sha256Api(api frontend.API, data ...frontend.Variable) frontend.Variable {
	sha := New(api)
	sha.Write(data[:])
	return sha.Sum()
}

func New(api frontend.API) Digest {
	res := Digest{}
	res.id = ecc.BN254
	res.api = api
	res.nx = 0
	res.len = 0
	res.Reset()
	return res
}

// p: byte array
func (d *Digest) Write(p []frontend.Variable) (nn int, err error) {
	var in []keccakf.Xuint8
	for i := range p {
		in = append(in, keccakf.NewUint8API(d.api).AsUint8(p[i]))
	}
	return d.write(in)

}

func (d *Digest) write(p []keccakf.Xuint8) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)

	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			blockGeneric(d, d.x[:]...)
			d.nx = 0
		}
		p = p[n:]
	}

	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		blockGeneric(d, p[:n]...)
		p = p[n:]
	}

	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}

	return
}

func (d *Digest) Sum() frontend.Variable {
	d0 := *d
	hash := d0.checkSum()
	return hash
}

func (d *Digest) checkSum() frontend.Variable {
	l := d.len
	var tmp [64]keccakf.Xuint8
	tmp[0] = keccakf.ConstUint8(0x80)
	for i := 1; i < 64; i++ {
		tmp[i] = keccakf.ConstUint8(0x0)
	}
	if l%64 < 56 {
		_, err := d.write(tmp[0 : 56-l%64])
		if err != nil {
			panic(fmt.Sprint("err during sha256 hash calculation", err))
		}
	} else {
		_, err := d.write(tmp[0 : 64+56-l%64])
		if err != nil {
			panic(fmt.Sprint("err during sha256 hash calculation", err))
		}
	}
	msgLen := l * 8

	bits := d.api.ToBinary(msgLen, 64) // 64 bit = 8 byte
	for i, j := 7, 0; i >= 0; i, j = i-1, j+1 {
		start := i * 8
		copy(tmp[j][:], bits[start : start+8][:])
	}
	_, err := d.write(tmp[0:8])
	if err != nil {
		panic(fmt.Sprint("err during sha256 hash calculation", err))
	}
	fmt.Printf("block number:%d\n", d.len/64)

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	uapi32 := keccakf.NewUint32API(d.api)
	hashBytes := [][]keccakf.Xuint8{
		toBytes(*uapi32, d.h[0]),
		toBytes(*uapi32, d.h[1]),
		toBytes(*uapi32, d.h[2]),
		toBytes(*uapi32, d.h[3]),
		toBytes(*uapi32, d.h[4]),
		toBytes(*uapi32, d.h[5]),
		toBytes(*uapi32, d.h[6]),
		toBytes(*uapi32, d.h[7]),
	}
	var res []keccakf.Xuint8
	for i := 0; i < 8; i++ {
		res = append(res, hashBytes[i]...)
	}
	res = res[0:32]

	var sha256Bits []frontend.Variable
	for i := len(res) - 1; i >= 0; i-- {
		sha256Bits = append(sha256Bits, res[i][:]...)
	}

	return d.api.FromBinary(sha256Bits[:]...)
}

func toBytes(uapi32 keccakf.Uint32api, x keccakf.Xuint32) []keccakf.Xuint8 {
	return uapi32.EncodeToXuint8BigEndian(x)
}
