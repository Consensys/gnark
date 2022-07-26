package emulated

import (
	"crypto/rand"
	"math"
	"math/big"
	"math/bits"
	mrand "math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	k           = 256                   // The exact number of bits required to represent the prime modulus
	nbLimbs     = 4                     // The exact number of words required to represent the prime modulus
	bitsPerLimb = 64                    // The word-size of the representation
	m           = nbLimbs * bitsPerLimb // The total number of bits in a word
)

var p *big.Int

type element [nbLimbs]*big.Int

var (
	rSquare  element
	qInverse element
	qElement element
)

var mLowW *big.Int

// Completely Reduced Numbers: the numbers from 0 to (p − 1).
// Incompletely Reduced Numbers: the numbers from 0 to (2ᵐ − 1).
// Unreduced Numbers: the numbers from p to (2ᵐ − 1).

func init() {
	p, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	rSquare.init()
	qInverse.init()
	qElement.init()

	_r := big.NewInt(1)
	_r.Lsh(_r, m)
	_rInv := big.NewInt(1)
	_qInv := big.NewInt(0)
	extendedEuclideanAlgo(_r, p, _rInv, _qInv)
	_qInv.Mod(_qInv, _r)

	// rsquare
	_rSquare := big.NewInt(2)
	exponent := big.NewInt(m * 2)
	_rSquare.Exp(_rSquare, exponent, p)

	// mask for low w bits
	mLowW = big.NewInt(1)
	mLowW.Lsh(mLowW, bitsPerLimb).Sub(mLowW, big.NewInt(1))

	qInverse.fromBigInt(_qInv)
	rSquare.fromBigInt(_rSquare)
	qElement.fromBigInt(p)
}

func (e *element) init() {
	for i := 0; i < len(e); i++ {
		e[i] = new(big.Int)
	}
}

func (e *element) fromBigInt(v *big.Int) {
	err := decompose(v, bitsPerLimb, e[:])
	if err != nil {
		panic(err)
	}
}

func (e *element) fromMont() {
	var one element
	one.init()
	one[0].SetUint64(1)
	e.mulCIOS(e, &one)
}

func (e *element) toMont() {
	e.mulCIOS(e, &rSquare)
}

func (e *element) isGreaterThanP() bool {

	i := len(e) - 1
	for i > 0 && e[i].Cmp(qElement[i]) == 0 {
		i--
	}

	return e[i].Cmp(qElement[i]) != -1
}

func (e *element) subp() {
	r := new(big.Int)
	err := recompose(e[:], bitsPerLimb, r)
	if err != nil {
		panic(err)
	}

	r.Sub(r, p)
	if err := decompose(r, bitsPerLimb, e[:]); err != nil {
		panic(err)
	}
}

func (e *element) mulCIOS(x, y *element) {
	// for i=0 to N-1
	// 		C := 0
	// 		for j=0 to N-1
	// 			(C,t[j]) := t[j] + x[j]*y[i] + C
	// 		(t[N+1],t[N]) := t[N] + C
	//
	// 		C := 0
	// 		m := t[0]*q'[0] mod D
	// 		(C,_) := t[0] + m*q[0]
	// 		for j=1 to N-1
	// 			(C,t[j-1]) := t[j] + m*q[j] + C
	//
	// 		(C,t[N-1]) := t[N] + C
	// 		t[N] := t[N+1] + C
	t := make([]*big.Int, nbLimbs+2)
	for i := 0; i < len(t); i++ {
		t[i] = new(big.Int)
	}
	// addW: 2 api.Mul (assert is bool on carry & sum + carry weighted = sum(a,b)) (maybe 1 if we don't assert bool)
	// mulW: 1 constraint; assert weighted product == product (need product to fit in native limbs)
	// madd2: 5 constraintes

	// counts:
	// nbLimbs * ((nbLimbs * madd2 * 2) + 3 * addW + mulW  )
	//
	for i := 0; i < nbLimbs; i++ {
		C := big.NewInt(0)

		for j := 0; j < nbLimbs; j++ {
			C, t[j] = madd2(x[j], y[i], t[j], C)
		}
		t[nbLimbs], t[nbLimbs+1] = addW(t[nbLimbs], C)
		C.SetUint64(0)
		_, m := mulW(t[0], qInverse[0])

		C, _ = madd2(m, qElement[0], t[0], C)
		for j := 1; j < nbLimbs; j++ {
			C, t[j-1] = madd2(m, qElement[j], t[j], C)
		}
		t[nbLimbs-1], C = addW(t[nbLimbs], C)
		t[nbLimbs], _ = addW(t[nbLimbs+1], C)
	}

	if t[nbLimbs].Cmp(big.NewInt(0)) != 0 {
		r := new(big.Int)
		err := recompose(t[:nbLimbs], bitsPerLimb, r)
		if err != nil {
			panic(err)
		}

		r.Sub(r, p)
		e.fromBigInt(r)
		return
	}

	copy(e[:], t[:])
	if e.isGreaterThanP() {
		// we need to reduce
		e.subp()
	}

}

func (e *element) toBigInt() *big.Int {
	r := new(big.Int)
	err := recompose(e[:], bitsPerLimb, r)
	if err != nil {
		panic(err)
	}
	return r
}

type testData struct {
	a, b, res *big.Int
}

func generateTestData() (r []testData) {
	for i := 0; i < 10; i++ {
		a, _ := rand.Int(rand.Reader, p)
		b, _ := rand.Int(rand.Reader, p)
		res := new(big.Int).Mul(a, b)
		res.Mod(res, p)
		r = append(r, testData{a: a, b: b, res: res})
	}
	return
}

func TestMontMul(t *testing.T) {
	assert := require.New(t)
	tt := generateTestData()

	for _, tData := range tt {
		var ea, eb, eres element
		ea.init()
		eb.init()
		eres.init()

		ea.fromBigInt(tData.a)
		eb.fromBigInt(tData.b)

		ea.toMont()
		ea.fromMont()
		ra := ea.toBigInt()
		assert.True(ra.Cmp(tData.a) == 0, "can't reconstruct (toMont / fromMont) -> big.Int")

		eb.toMont()
		eb.fromMont()
		rb := eb.toBigInt()
		assert.True(rb.Cmp(tData.b) == 0)

		ea.toMont()
		eb.toMont()
		eres.mulCIOS(&ea, &eb)
		eres.fromMont()
		rres := eres.toBigInt()
		assert.True(rres.Cmp(tData.res) == 0, "mul failed")
	}
}

// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
// r > q, modifies rinv and qinv such that rinv.r - qinv.q = 1
func extendedEuclideanAlgo(r, q, rInv, qInv *big.Int) {
	var s1, s2, t1, t2, qi, tmpMuls, riPlusOne, tmpMult, a, b big.Int
	t1.SetUint64(1)
	rInv.Set(big.NewInt(1))
	qInv.Set(big.NewInt(0))
	a.Set(r)
	b.Set(q)

	// r_i+1 = r_i-1 - q_i.r_i
	// s_i+1 = s_i-1 - q_i.s_i
	// t_i+1 = t_i-1 - q_i.s_i
	for b.Sign() > 0 {
		qi.Div(&a, &b)
		riPlusOne.Mod(&a, &b)

		tmpMuls.Mul(&s1, &qi)
		tmpMult.Mul(&t1, &qi)

		s2.Set(&s1)
		t2.Set(&t1)

		s1.Sub(rInv, &tmpMuls)
		t1.Sub(qInv, &tmpMult)
		rInv.Set(&s2)
		qInv.Set(&t2)

		a.Set(&b)
		b.Set(&riPlusOne)
	}
	qInv.Neg(qInv)
}

func addW(a, b *big.Int) (r, carry *big.Int) {
	r = new(big.Int)
	r.Add(a, b)
	carry = new(big.Int)
	carry.Rsh(r, bitsPerLimb)
	r.And(r, mLowW)
	return
}

func mulW(a, b *big.Int) (hi, lo *big.Int) {
	lo = new(big.Int)
	hi = new(big.Int)
	lo.Mul(a, b)
	hi.Rsh(lo, bitsPerLimb)
	lo.And(lo, mLowW)
	return
}

func madd2(a, b, c, d *big.Int) (*big.Int, *big.Int) {
	hi, lo := mulW(a, b)
	c, carry := addW(c, d)
	hi, _ = addW(hi, carry)
	lo, carry = addW(lo, c)
	hi, _ = addW(hi, carry)

	return hi, lo
}

// madd2 hi, lo = a*b + c + d
func _madd2(a, b, c, d uint64) (hi uint64, lo uint64) {
	var carry uint64
	hi, lo = bits.Mul64(a, b)
	c, carry = bits.Add64(c, d, 0)
	hi, _ = bits.Add64(hi, 0, carry)
	lo, carry = bits.Add64(lo, c, 0)
	hi, _ = bits.Add64(hi, 0, carry)
	return
}

func TestAddMulW(t *testing.T) {
	assert := require.New(t)

	if bitsPerLimb != 64 {
		t.Skip()
	}

	for i := 0; i < 1000; i++ {
		a := mrand.Uint64()
		b := mrand.Uint64()
		c := mrand.Uint64()
		d := mrand.Uint64()
		if i == 0 {
			a = math.MaxUint64
			b = math.MaxUint64
			c = math.MaxUint64
			d = math.MaxUint64
		} else if i%2 == 0 {
			b = math.MaxUint64
		}
		if i%3 == 0 {
			c = math.MaxUint64
		}
		if i%5 == 0 {
			d = math.MaxUint64
		}

		ba := new(big.Int).SetUint64(a)
		bb := new(big.Int).SetUint64(b)
		bc := new(big.Int).SetUint64(c)
		bd := new(big.Int).SetUint64(d)

		sum, carry := bits.Add64(a, b, 0)
		bsum, bcarry := addW(ba, bb)

		assert.True(bsum.IsUint64())
		assert.True(bcarry.IsUint64())
		assert.True(bcarry.Uint64() == carry)
		assert.True(bsum.Uint64() == sum)

		hi, lo := bits.Mul64(a, b)
		bhi, blo := mulW(ba, bb)
		assert.True(bhi.IsUint64())
		assert.True(blo.IsUint64())
		assert.True(bhi.Uint64() == hi)
		assert.True(blo.Uint64() == lo)

		hi, lo = _madd2(a, b, c, d)
		bhi, blo = madd2(ba, bb, bc, bd)
		assert.True(bhi.IsUint64())
		assert.True(blo.IsUint64())
		assert.True(bhi.Uint64() == hi)
		assert.True(blo.Uint64() == lo)
	}

}
