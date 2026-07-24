package sw_bn254

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/smallfields"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/math/emulated"
)

// Fixed-base signed-digit comb for compile-time constant G2 points, following
// the same construction and soundness argument as the G1 comb in
// sw_emulated/fixedbase.go: odd recode k' = s + 1 − b0 pinned by a single
// mod-r assertion, constant window tables [d(j)·2^{w·t}]P selected by one-hot
// flags shared across all coordinate limbs, provably collision-free
// incomplete chord additions over E2, parity fold in the top window, and a
// complete AddUnified tail.
const g2CombWindow = 8

type g2CombData struct {
	w         int
	nw        int
	n         int
	nbUnified int
	// windows[t][j] = [d(j)·2^{w·t} mod r]P as (X.A0, X.A1, Y.A0, Y.A1)
	windows [][][4]*big.Int
	topEven [][4]*big.Int
}

var g2CombCache sync.Map

func g2CombDataFor(x0, x1, y0, y1 *big.Int) (*g2CombData, error) {
	key := x0.Text(16) + "|" + x1.Text(16) + "|" + y0.Text(16) + "|" + y1.Text(16)
	if v, ok := g2CombCache.Load(key); ok {
		return v.(*g2CombData), nil
	}
	var P bn254.G2Affine
	P.X.A0.SetBigInt(x0)
	P.X.A1.SetBigInt(x1)
	P.Y.A0.SetBigInt(y0)
	P.Y.A1.SetBigInt(y1)
	if P.IsInfinity() {
		return nil, errors.New("base point is the point at infinity")
	}
	if !P.IsOnCurve() {
		return nil, errors.New("base point is not on the twist")
	}
	if !P.IsInSubGroup() {
		return nil, errors.New("base point is not in the prime-order subgroup")
	}
	w := g2CombWindow
	r := fr_bn.Modulus()
	rBits := r.BitLen()
	nw := (rBits + w - 1) / w
	n := w * nw
	var frParams ScalarField
	if n > int(frParams.NbLimbs()*frParams.BitsPerLimb()) {
		return nil, errors.New("recoded scalar exceeds scalar field emulation capacity")
	}
	nbUnified := 0
	for t := nw - 1; t >= 1; t-- {
		if new(big.Int).Lsh(big.NewInt(1), uint(w*(t+1))).Cmp(r) <= 0 {
			break
		}
		nbUnified++
	}
	nbUnified = max(nbUnified, 1)

	toBig := func(a *bn254.G2Affine) ([4]*big.Int, error) {
		if a.IsInfinity() {
			return [4]*big.Int{}, errors.New("unexpected point at infinity in comb table")
		}
		return [4]*big.Int{
			a.X.A0.BigInt(new(big.Int)),
			a.X.A1.BigInt(new(big.Int)),
			a.Y.A0.BigInt(new(big.Int)),
			a.Y.A1.BigInt(new(big.Int)),
		}, nil
	}

	half := 1 << (w - 1)
	windows := make([][][4]*big.Int, nw)
	var Bt bn254.G2Jac
	Bt.FromAffine(&P)
	for t := 0; t < nw; t++ {
		if t > 0 {
			for k := 0; k < w; k++ {
				Bt.DoubleAssign()
			}
		}
		var D bn254.G2Jac
		D.Set(&Bt).DoubleAssign()
		odd := make([]bn254.G2Affine, half)
		acc := new(bn254.G2Jac).Set(&Bt)
		odd[0].FromJacobian(acc)
		for m := 1; m < half; m++ {
			acc.AddAssign(&D)
			odd[m].FromJacobian(acc)
		}
		tab := make([][4]*big.Int, 1<<w)
		for j := range tab {
			d := 2*j - (1 << w) + 1
			var e bn254.G2Affine
			if d > 0 {
				e = odd[(d-1)/2]
			} else {
				e.Neg(&odd[(-d-1)/2])
			}
			c, err := toBig(&e)
			if err != nil {
				return nil, err
			}
			tab[j] = c
		}
		windows[t] = tab
	}
	var negP bn254.G2Jac
	var negPAff bn254.G2Affine
	negPAff.Neg(&P)
	negP.FromAffine(&negPAff)
	topEven := make([][4]*big.Int, 1<<w)
	for j := range topEven {
		var e bn254.G2Affine
		e.X.A0.SetBigInt(windows[nw-1][j][0])
		e.X.A1.SetBigInt(windows[nw-1][j][1])
		e.Y.A0.SetBigInt(windows[nw-1][j][2])
		e.Y.A1.SetBigInt(windows[nw-1][j][3])
		var acc bn254.G2Jac
		acc.FromAffine(&e)
		acc.AddAssign(&negP)
		var res bn254.G2Affine
		res.FromJacobian(&acc)
		c, err := toBig(&res)
		if err != nil {
			return nil, fmt.Errorf("parity-fold table: %w", err)
		}
		topEven[j] = c
	}
	d := &g2CombData{
		w:         w,
		nw:        nw,
		n:         n,
		nbUnified: nbUnified,
		windows:   windows,
		topEven:   topEven,
	}
	g2CombCache.Store(key, d)
	return d, nil
}

// g2CombOneHot returns the 2^len(bs) one-hot indicator vector of the
// little-endian boolean bits bs (2^len(bs) − 2 constraints).
func g2CombOneHot(api frontend.API, bs []frontend.Variable) []frontend.Variable {
	flags := []frontend.Variable{1}
	for _, b := range bs {
		next := make([]frontend.Variable, 2*len(flags))
		if len(flags) == 1 {
			next[0] = api.Sub(1, b)
			next[1] = b
		} else {
			for j := range flags {
				hi := api.Mul(flags[j], b)
				next[j] = api.Sub(flags[j], hi)
				next[j+len(flags)] = hi
			}
		}
		flags = next
	}
	return flags
}

// g2CombSelect selects the table entry indexed by the bits, splitting the
// index into row and column one-hots so that the column flags combine with
// the constant limbs into free affine forms; every selected limb is a convex
// combination of constant limbs and needs no range check.
func (g2 *G2) g2CombSelect(table [][4]*big.Int, bs []frontend.Variable) g2AffP {
	var fp BaseField
	nbLimbs := int(fp.NbLimbs())
	nbBits := fp.BitsPerLimb()
	w := len(bs)
	if len(table) != 1<<w {
		panic("table size mismatch")
	}
	nbOut := 4 * nbLimbs
	oneHotCost := func(k int) int {
		if k <= 1 {
			return 0
		}
		return 1<<k - 2
	}
	rb := 0
	bestCost := oneHotCost(w)
	for cand := 1; cand <= w; cand++ {
		cost := oneHotCost(cand) + oneHotCost(w-cand) + (1<<cand)*nbOut
		if cost < bestCost {
			bestCost = cost
			rb = cand
		}
	}
	rows := g2CombOneHot(g2.api, bs[:rb])
	cols := g2CombOneHot(g2.api, bs[rb:])

	tabLimbs := make([][4][]*big.Int, len(table))
	for j := range table {
		for coord := 0; coord < 4; coord++ {
			res := make([]*big.Int, nbLimbs)
			for i := range res {
				res[i] = new(big.Int)
			}
			if err := limbs.Decompose(table[j][coord], nbBits, res); err != nil {
				panic(err)
			}
			tabLimbs[j][coord] = res
		}
	}

	selLimb := func(coord, limb int) frontend.Variable {
		inner := make([]frontend.Variable, len(rows))
		for i := range rows {
			terms := make([]frontend.Variable, len(cols))
			for j := range cols {
				terms[j] = g2.api.Mul(cols[j], tabLimbs[i+(j<<rb)][coord][limb])
			}
			if len(terms) == 1 {
				inner[i] = terms[0]
			} else {
				inner[i] = g2.api.Add(terms[0], terms[1], terms[2:]...)
			}
		}
		if len(rows) == 1 {
			return inner[0]
		}
		out := make([]frontend.Variable, len(rows))
		for i := range rows {
			out[i] = g2.api.Mul(rows[i], inner[i])
		}
		return g2.api.Add(out[0], out[1], out[2:]...)
	}

	comp := func(coord int) *emulated.Element[BaseField] {
		ls := make([]frontend.Variable, nbLimbs)
		for l := 0; l < nbLimbs; l++ {
			ls[l] = selLimb(coord, l)
		}
		return g2.fp.UnsafeFromLimbs(ls)
	}
	return g2AffP{
		X: fields_bn254.E2{A0: *comp(0), A1: *comp(1)},
		Y: fields_bn254.E2{A0: *comp(2), A1: *comp(3)},
	}
}

// g2CombAdd is the incomplete chord addition over E2 (complete on the comb
// chain by the collision-freeness argument).
func (g2 *G2) g2CombAdd(p, q *g2AffP) *g2AffP {
	lam := g2.Ext2.DivUnchecked(g2.Ext2.Sub(&q.Y, &p.Y), g2.Ext2.Sub(&q.X, &p.X))
	xr := g2.Ext2.Sub(g2.Ext2.Square(lam), g2.Ext2.Add(&p.X, &q.X))
	yr := g2.Ext2.Sub(g2.Ext2.Mul(lam, g2.Ext2.Sub(&p.X, xr)), &p.Y)
	return &g2AffP{X: *xr, Y: *yr}
}

// scalarMulComb computes [s]P for the constant base point of the tables d.
// It returns (0,0) when s ≡ 0 (mod r).
func (g2 *G2) scalarMulComb(d *g2CombData, s *Scalar) *G2Affine {
	w, n, nw := d.w, d.n, d.nw
	rets, err := g2.fr.NewHintWithNativeOutput(g2CombRecodeHint, 1+n, s)
	if err != nil {
		panic(fmt.Sprintf("comb recode hint: %v", err))
	}
	b0 := rets[0]
	cbits := rets[1:]
	// FromBits constrains all bits (and b0) to be boolean; the single mod-r
	// assertion 2c + b0 ≡ s + 2^n pins k' = s + 1 − b0 modulo r, so the hint
	// only affects completeness.
	cEl := g2.fr.FromBits(cbits...)
	b0El := g2.fr.FromBits(b0)
	lhs := g2.fr.Add(g2.fr.MulConst(cEl, big.NewInt(2)), b0El)
	rhs := g2.fr.Add(s, g2.fr.NewElement(new(big.Int).Lsh(big.NewInt(1), uint(n))))
	g2.fr.AssertIsEqual(lhs, rhs)

	pts := make([]g2AffP, nw)
	for t := 0; t < nw-1; t++ {
		pts[t] = g2.g2CombSelect(d.windows[t], cbits[t*w:(t+1)*w])
	}
	stacked := make([][4]*big.Int, 0, 2<<w)
	stacked = append(stacked, d.topEven...)
	stacked = append(stacked, d.windows[nw-1]...)
	topBits := make([]frontend.Variable, 0, w+1)
	topBits = append(topBits, cbits[(nw-1)*w:]...)
	topBits = append(topBits, b0)
	pts[nw-1] = g2.g2CombSelect(stacked, topBits)

	nbInc := nw - 1 - d.nbUnified
	acc := &pts[0]
	for t := 1; t <= nbInc; t++ {
		acc = g2.g2CombAdd(acc, &pts[t])
	}
	res := &G2Affine{P: *acc}
	for t := nbInc + 1; t <= nw-1; t++ {
		res = g2.AddUnified(res, &G2Affine{P: pts[t]})
	}
	return res
}

// g2CombTryConst returns the comb tables when Q is a compile-time constant
// finite G2 subgroup point and the comb is supported in the current
// compilation context; otherwise ok is false.
func (g2 *G2) g2CombTryConst(Q *G2Affine) (*g2CombData, bool) {
	if smallfields.IsSmallField(g2.api.Compiler().Field()) {
		return nil, false
	}
	x0, ok := g2.fp.ConstantValue(&Q.P.X.A0)
	if !ok {
		return nil, false
	}
	x1, ok := g2.fp.ConstantValue(&Q.P.X.A1)
	if !ok {
		return nil, false
	}
	y0, ok := g2.fp.ConstantValue(&Q.P.Y.A0)
	if !ok {
		return nil, false
	}
	y1, ok := g2.fp.ConstantValue(&Q.P.Y.A1)
	if !ok {
		return nil, false
	}
	d, err := g2CombDataFor(x0, x1, y0, y1)
	if err != nil {
		return nil, false
	}
	return d, true
}

// g2CombRecodeHint computes the comb recoding of the scalar (see the G1
// version in sw_emulated).
func g2CombRecodeHint(_ *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHintWithNativeOutput(inputs, outputs, func(r *big.Int, in, out []*big.Int) error {
		if len(in) != 1 {
			return errors.New("expecting one input")
		}
		if len(out) < 2 {
			return errors.New("expecting at least two outputs")
		}
		n := len(out) - 1
		s := new(big.Int).Mod(in[0], r)
		b0 := s.Bit(0)
		kp := new(big.Int).Set(s)
		if b0 == 0 {
			kp.Add(kp, big.NewInt(1))
		}
		cv := new(big.Int).Lsh(big.NewInt(1), uint(n))
		cv.Sub(cv, big.NewInt(1)).Add(cv, kp).Rsh(cv, 1)
		out[0].SetUint64(uint64(b0))
		for i := 0; i < n; i++ {
			out[1+i].SetUint64(uint64(cv.Bit(i)))
		}
		return nil
	})
}
