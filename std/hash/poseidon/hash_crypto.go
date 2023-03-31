package poseidon

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"hash"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	BlockSize = fr.Bytes // BlockSize size that mimc consumes
)

// digest represents the partial evaluation of the checksum
// along with the params of the mimc function
type digest struct {
	data []*fr.Element // data to hash
}

// NewPoseidon returns a MiMCImpl object, pure-go reference implementation
func NewPoseidon() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	d.data = nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (d *digest) Sum(b []byte) []byte {
	buffer := d.checksum()
	d.data = nil // flush the data already hashed
	hash := buffer.Bytes()
	b = append(b, hash[:]...)
	return b
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (d *digest) Size() int {
	return BlockSize
}

// BlockSize returns the number of bytes Sum will return.
func (d *digest) BlockSize() int {
	return BlockSize
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
//
// Each []byte block of size BlockSize represents a big endian fr.Element.
//
// If len(p) is not a multiple of BlockSize and any of the []byte in p represent an integer
// larger than fr.Modulus, this function returns an error.
//
// To hash arbitrary data ([]byte not representing canonical field elements) use fr.Hash first
func (d *digest) Write(p []byte) (int, error) {

	var start int
	for start = 0; start < len(p); start += BlockSize {
		if elem, err := fr.BigEndian.Element((*[BlockSize]byte)(p[start : start+BlockSize])); err == nil {
			d.data = append(d.data, &elem)
		} else {
			return 0, err
		}
	}

	if start != len(p) {
		return 0, errors.New("invalid input length: must represent a list of field elements, expects a []byte of len m*BlockSize")
	}
	return len(p), nil
}

func (d *digest) checksum() *fr.Element {
	return poseidon.Poseidon(d.data...)
}

// WriteString writes a string that doesn't necessarily consist of field elements
func (d *digest) WriteString(rawBytes []byte) {
	if elems, err := fr.Hash(rawBytes, []byte("string:"), 1); err != nil {
		panic(err)
	} else {
		d.data = append(d.data, &elems[0])
	}
}
