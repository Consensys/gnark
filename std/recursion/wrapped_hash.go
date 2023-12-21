package recursion

import (
	"bytes"
	"fmt"
	"hash"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	cryptomimc "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	stdhash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
	"golang.org/x/exp/slices"
)

type shortNativeHash struct {
	wrapped hash.Hash

	outSize      int
	bitBlockSize int

	ringBuf *bytes.Buffer
	buf     []byte
}

// NewShort returns a native hash function which reads elements in the current native
// field and outputs element in the target field (usually the scalar field of
// the circuit being recursed). The hash function is based on MiMC and
// partitions the excess bits to not overflow the target field.
func NewShort(current, target *big.Int) (hash.Hash, error) {
	var h cryptomimc.Hash
	var bitBlockSize int
	switch current.String() {
	case ecc.BN254.ScalarField().String():
		h = cryptomimc.MIMC_BN254
		bitBlockSize = ecc.BN254.ScalarField().BitLen()
	case ecc.BLS12_381.ScalarField().String():
		h = cryptomimc.MIMC_BLS12_381
		bitBlockSize = ecc.BLS12_381.ScalarField().BitLen()
	case ecc.BLS12_377.ScalarField().String():
		h = cryptomimc.MIMC_BLS12_377
		bitBlockSize = ecc.BLS12_377.ScalarField().BitLen()
	case ecc.BLS12_378.ScalarField().String():
		h = cryptomimc.MIMC_BLS12_378
		bitBlockSize = ecc.BLS12_378.ScalarField().BitLen()
	case ecc.BW6_761.ScalarField().String():
		h = cryptomimc.MIMC_BW6_761
		bitBlockSize = ecc.BW6_761.ScalarField().BitLen()
	case ecc.BLS24_315.ScalarField().String():
		h = cryptomimc.MIMC_BLS24_315
		bitBlockSize = ecc.BLS24_315.ScalarField().BitLen()
	case ecc.BLS24_317.ScalarField().String():
		h = cryptomimc.MIMC_BLS24_317
		bitBlockSize = ecc.BLS24_317.ScalarField().BitLen()
	case ecc.BW6_633.ScalarField().String():
		h = cryptomimc.MIMC_BW6_633
		bitBlockSize = ecc.BW6_633.ScalarField().BitLen()
	case ecc.BW6_756.ScalarField().String():
		h = cryptomimc.MIMC_BW6_756
		bitBlockSize = ecc.BW6_756.ScalarField().BitLen()
	default:
		return nil, fmt.Errorf("no default mimc for scalar field: %s", current.String())
	}
	hh := h.New()
	if target.Cmp(current) == 0 {
		return hh, nil
	}
	nbBits := target.BitLen()
	if nbBits > current.BitLen() {
		nbBits = current.BitLen()
	}
	return newShortFromParam(hh, bitBlockSize, nbBits), nil
}

func newShortFromParam(hf hash.Hash, bitBlockSize, outSize int) hash.Hash {

	// TODO: right now assume bitLength is the modulus bit length. We subtract within
	return &shortNativeHash{
		wrapped:      hf,
		outSize:      outSize,
		bitBlockSize: bitBlockSize,
		buf:          make([]byte, (bitBlockSize+7)/8),
		ringBuf:      new(bytes.Buffer),
	}
}

func (h *shortNativeHash) Write(p []byte) (n int, err error) {
	// we first write to the buffer. We want to be able to partition the inputs
	// into smaller parts and buffer is good to keep track of the excess.
	h.ringBuf.Write(p) // nosec: doesnt fail
	for h.ringBuf.Len() >= (len(h.buf) - 1) {
		// the buffer contains now enough bytes so that we can write it to the
		// underlying hash.
		h.ringBuf.Read(h.buf[1:])
		h.wrapped.Write(h.buf)
	}
	return len(p), nil
}

func (h *shortNativeHash) Sum(b []byte) []byte {
	// the cache buffer may contain still something. Write everything into the
	// underlying hasher before we digest.

	// zero the buffer we use for transporting bytes from bytes.Buffer to
	// underlying hash. Remember that the cache buffer may not be full.
	for i := range h.buf {
		h.buf[i] = 0
	}
	h.ringBuf.Read(h.buf[1:])
	h.wrapped.Write(h.buf)

	// cut the hash a byte short to definitely fit
	res := h.wrapped.Sum(nil)
	nbBytes := (h.outSize+7)/8 - 1
	res = res[len(res)-nbBytes:]
	return append(b, res...)
}

func (h *shortNativeHash) Reset() {
	h.ringBuf.Reset()
	h.buf = make([]byte, (h.bitBlockSize+7)/8)
	h.wrapped.Reset()
}

func (h *shortNativeHash) Size() int {
	return (int(h.outSize)+7)/8 - 1
}

func (h *shortNativeHash) BlockSize() int {
	return h.wrapped.BlockSize() - 1
}

type shortCircuitHash struct {
	api     frontend.API
	outSize int
	wrapped stdhash.FieldHasher
	buf     []frontend.Variable
	tmp     []frontend.Variable
	bitmode bool
}

func newHashFromParameter(api frontend.API, hf stdhash.FieldHasher, bitLength int, bitmode bool) stdhash.FieldHasher {
	tmp := make([]frontend.Variable, ((api.Compiler().FieldBitLen()+7)/8)*8-8)
	for i := range tmp {
		tmp[i] = 0
	}
	return &shortCircuitHash{
		api:     api,
		outSize: bitLength,
		wrapped: hf,
		tmp:     tmp,
		bitmode: bitmode,
	}
}

// NewHash returns a circuit hash function which reads elements in the current
// native field and outputs element in the target field (usually the scalar
// field of the circuit being recursed). The hash function is based on MiMC and
// partitions the excess bits to not overflow the target field.
func NewHash(api frontend.API, target *big.Int, bitmode bool) (stdhash.FieldHasher, error) {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return nil, fmt.Errorf("get mimc: %w", err)
	}
	if api.Compiler().Field().Cmp(target) == 0 {
		return &h, nil
	}
	nbBits := target.BitLen()
	if nbBits > api.Compiler().FieldBitLen() {
		nbBits = api.Compiler().FieldBitLen()
	}
	return newHashFromParameter(api, &h, nbBits, bitmode), nil
}

// NewTranscript returns a new Fiat-Shamir transcript for computing bound
// challenges. It uses hasher returned by [NewHash] internally and configures
// the transcript to be compatible with gnark-crypto Fiat-Shamir transcript.
func NewTranscript(api frontend.API, target *big.Int, challenges []string) (*fiatshamir.Transcript, error) {
	h, err := NewHash(api, target, true)
	if err != nil {
		return nil, fmt.Errorf("new hash: %w", err)
	}
	nbBits := target.BitLen()
	if nbBits > api.Compiler().FieldBitLen() {
		nbBits = api.Compiler().FieldBitLen()
	}
	fs := fiatshamir.NewTranscript(api, h, challenges, fiatshamir.WithTryBitmode(((nbBits+7)/8)*8-8))
	return fs, nil
}

func (h *shortCircuitHash) Sum() frontend.Variable {
	// before we compute the digest we have to write the rest of the buffer into
	// the underlying hash. We know that we have maximum one variable left, as
	// otherwise we would have written in the [Write] method.

	// but first, we have to zero the buffer we use for reversing. The cache
	// buffer may not be full and so some bits may be set.
	for i := range h.tmp {
		h.tmp[i] = 0
	}
	copy(h.tmp, h.buf)
	slices.Reverse(h.tmp)
	v := bits.FromBinary(h.api, h.tmp)
	h.wrapped.Write(v)
	res := h.wrapped.Sum()
	resBts := bits.ToBinary(h.api, res)
	// XXX(ivokub): when changing the number of bits we construct the sum from
	// then consider downstream users of short-hash which may assume the number
	// of non-zero bits in the output. Most notably, we have the assumption in
	// the KZG FoldProof method to avoid doing full scalar mul.
	res = bits.FromBinary(h.api, resBts[:((h.outSize+7)/8-1)*8])
	return res
}

func (h *shortCircuitHash) Write(data ...frontend.Variable) {
	// tricky part - bits representation is little-endian, i.e. least
	// significant bit is at position zero. However, in the native version least
	// significant BYTE is at the highest position. When we decompose into bits,
	// then we first have to reverse the bits so that when we partition maximum
	// number of full bytes out so it would correspond to the native version.
	//
	// But this means that later we have to reverse again when we recompose.
	if h.bitmode {
		h.buf = append(h.buf, data...)
	} else {
		for i := range data {
			// h.tmp is maximum full number of bytes. This is one byte less than in
			// the native version (the bits are on full number of bytes). Luckily,
			// [bits.ToBinary] allows to decompose into arbitrary number of bits.
			bts := bits.ToBinary(h.api, data[i], bits.WithNbDigits(len(h.tmp)+8))
			// reverse to be in sync with native version when we later slice
			// len(h.tmp) bits.
			slices.Reverse(bts)
			// store in the buffer. At every round we try to write to the wrapped
			// hash as much as possible so the buffer isn't usually very big.
			h.buf = append(h.buf, bts...)
		}
	}
	for len(h.buf) >= len(h.tmp) {
		// OK, now there is sufficient number of bits we can write to hash
		// function. First we take the maximum number of full bytes.
		copy(h.tmp, h.buf[:len(h.tmp)])
		// and reverse it so that when recomposing is correct.
		slices.Reverse(h.tmp)
		v := bits.FromBinary(h.api, h.tmp)
		// write to the underlying hash and empty the buffer.
		h.wrapped.Write(v)
		h.buf = h.buf[len(h.tmp):]
	}
}

func (h *shortCircuitHash) Reset() {
	h.buf = nil
	for i := range h.tmp {
		h.tmp[i] = 0
	}
	h.wrapped.Reset()
}
