package sw

import (
	"fmt"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/tower"
	"github.com/consensys/gnark/std/algebra/tower/fp12"
	"github.com/consensys/gnark/std/algebra/tower/fp2"
	"github.com/consensys/gnark/std/algebra/tower/fp24"
)

type GT[T tower.Tower, B tower.Basis, PT tower.TowerPt[T, B], PB tower.BasisPt[B]] struct {
	E      T
	api    frontend.API
	config *innerConfig
}

func NewGT[T tower.Tower, B tower.Basis, PT tower.TowerPt[T, B], PB tower.BasisPt[B]](api frontend.API) (GT[T, B, PT, PB], error) {
	ret := GT[T, B, PT, PB]{
		api: api,
	}
	var err error
	ret.config, err = getInnerConfig(api.Curve())
	if err != nil {
		return ret, fmt.Errorf("get inner curve config: %w", err)
	}
	switch vv := (any)(&(ret.E)).(type) {
	case *fp12.E12:
		e, err := fp12.NewFp12Zero(api)
		if err != nil {
			return ret, fmt.Errorf("new fp12: %w", err)
		}
		*vv = e
	case *fp24.E24:
		e, err := fp24.NewFp24Zero(api)
		if err != nil {
			return ret, fmt.Errorf("new fp24: %w", err)
		}
		*vv = e
	}
	return ret, nil
}

type GTConstraint interface {
	bls12377.GT | bls24315.GT
}

func FromGT[T tower.Tower, B tower.Basis, PT tower.TowerPt[T, B], PB tower.BasisPt[B], C GTConstraint](p C) GT[T, B, PT, PB] {
	var ret GT[T, B, PT, PB]
	switch v := (any)(p).(type) {
	case bls12377.GT:
		retp, ok := (any)(&ret).(*GT[fp12.E12, fp2.E2])
		if !ok {
			panic("incompatible function type parameters")
		}
		retp.E = fp12.FromFp12(v)
	case bls24315.GT:
		retp, ok := (any)(&ret).(*GT[fp24.E24, fp24.E4])
		if !ok {
			panic("incompatible function type parameters")
		}
		retp.E = fp24.FromFp24(v)
	}
	return ret
}

func (gt *GT[T, B, PT, PB]) Pairing(p1 G1Affine, p2 G2Affine[B, PB]) *GT[T, B, PT, PB] {
	gt.WideMillerLoop(G1G2[B, PB]{p1, p2})
	PT(&(gt.E)).FinalExponentiation(gt.E, gt.config.ateLoop)
	// TODO: final exp using ate loop
	return gt
}

type lineEvaluation[B tower.Basis, PB tower.BasisPt[B]] struct {
	r0, r1 B
}

func newLine[B tower.Basis, PB tower.BasisPt[B]](api frontend.API) lineEvaluation[B, PB] {
	var r0, r1 B
	PB(&r0).SetAPI(api)
	PB(&r1).SetAPI(api)
	return lineEvaluation[B, PB]{r0, r1}
}

type G1G2[B tower.Basis, PB tower.BasisPt[B]] struct {
	g1 G1Affine
	g2 G2Affine[B, PB]
}

func (gt *GT[T, B, PT, PB]) WideMillerLoop(inputs ...G1G2[B, PB]) (*GT[T, B, PT, PB], error) {
	api := gt.api
	var err error
	// check that all results have api set and that the ate loops are same
	if len(inputs) == 0 {
		return nil, fmt.Errorf("at least single triplet must be given")
	}
	res := PT(&(gt.E))
	res.SetOne()

	l1 := newLine[B, PB](api)
	l2 := newLine[B, PB](api)
	Qacc := make([]G2Affine[B, PB], len(inputs))
	Qneg := make([]G2Affine[B, PB], len(inputs))
	for i := 0; i < len(inputs); i++ {
		Qacc[i], err = NewG2Affine[B, PB](api)
		if err != nil {
			panic("incompatible api")
		}
		Qneg[i], err = NewG2Affine[B, PB](api)
		if err != nil {
			panic("incompatible api")
		}
	}
	yInv := make([]frontend.Variable, len(inputs))
	xOverY := make([]frontend.Variable, len(inputs))

	for i := 0; i < len(inputs); i++ {
		Qacc[i].Set(inputs[i].g2)
		Qneg[i].Neg(inputs[i].g2)
		yInv[i] = api.DivUnchecked(1, inputs[i].g1.Y)
		xOverY[i] = api.DivUnchecked(inputs[i].g1.X, inputs[i].g1.Y)
	}

	for i := len(gt.config.ateLoopDecomposed) - 2; i >= 0; i-- {
		res.Square(*res)
		if gt.config.ateLoopDecomposed[i] == 0 {
			for k := 0; k < len(inputs); k++ {
				Qacc[k], l1 = doubleStep[T, PT](api, Qacc[k])
				PB(&(l1.r0)).MulByFp(l1.r0, xOverY[k])
				PB(&(l1.r1)).MulByFp(l1.r1, yInv[k])
				res.MulBy034(l1.r0, l1.r1)
			}
		} else if gt.config.ateLoopDecomposed[i] == 1 {
			for k := 0; k < len(inputs); k++ {
				Qacc[k], l1, l2 = doubleAndAddStep[T, PT](api, Qacc[k], inputs[k].g2)
				PB(&(l1.r0)).MulByFp(l1.r0, xOverY[k])
				PB(&(l1.r1)).MulByFp(l1.r1, yInv[k])
				res.MulBy034(l1.r0, l1.r1)
				PB(&(l2.r0)).MulByFp(l2.r0, xOverY[k])
				PB(&(l2.r1)).MulByFp(l2.r1, yInv[k])
				res.MulBy034(l2.r0, l2.r1)
			}
		} else {
			for k := 0; k < len(inputs); k++ {
				Qacc[k], l1, l2 = doubleAndAddStep[T, PT](api, Qacc[k], Qneg[k])
				PB(&(l1.r0)).MulByFp(l1.r0, xOverY[k])
				PB(&(l1.r1)).MulByFp(l1.r1, yInv[k])
				res.MulBy034(l1.r0, l1.r1)
				PB(&(l2.r0)).MulByFp(l2.r0, xOverY[k])
				PB(&(l2.r1)).MulByFp(l2.r1, yInv[k])
				res.MulBy034(l2.r0, l2.r1)
			}
		}
	}

	// TODO: when conjugate?
	// res.Conjugate(*res)
	PT(&(gt.E)).Set(*res)
	// forprint := (any)(res).(*fp12.E12)
	// api.Println(forprint.C0.B0.A0)
	// api.Println(forprint.C0.B0.A1)
	// api.Println(forprint.C0.B1.A0)
	// api.Println(forprint.C0.B1.A1)
	// api.Println(forprint.C0.B2.A0)
	// api.Println(forprint.C0.B2.A1)
	// api.Println(forprint.C1.B0.A0)
	// api.Println(forprint.C1.B0.A1)
	// api.Println(forprint.C1.B1.A0)
	// api.Println(forprint.C1.B1.A1)
	// api.Println(forprint.C1.B2.A0)
	// api.Println(forprint.C1.B2.A1)

	return gt, nil
}

func doubleAndAddStep[T tower.Tower, PT tower.TowerPt[T, B], B tower.Basis, PB tower.BasisPt[B]](api frontend.API, p1, p2 G2Affine[B, PB]) (G2Affine[B, PB], lineEvaluation[B, PB], lineEvaluation[B, PB]) {
	line1 := newLine[B, PB](api)
	line2 := newLine[B, PB](api)
	var n, d, l1, l2, x3, x4, y4 B
	PB(&n).SetAPI(api)
	PB(&d).SetAPI(api)
	PB(&l1).SetAPI(api)
	PB(&l2).SetAPI(api)
	PB(&x3).SetAPI(api)
	PB(&x4).SetAPI(api)
	PB(&y4).SetAPI(api)

	res, err := NewG2Affine[B, PB](api)
	if err != nil {
		// this is internal step. API is already checked in higher stack
		panic("incompatible api")
	}

	// compute lambda1 = (y2-y1)/(x2-x1)
	PB(&n).Sub(p1.Y, p2.Y)
	PB(&d).Sub(p1.X, p2.X)
	PB(&l1).Inverse(d)
	PB(&l1).Mul(l1, n)

	// x3 =lambda1**2-p1.x-p2.x
	PB(&x3).Square(l1)
	PB(&x3).Sub(x3, p1.X)
	PB(&x3).Sub(x3, p2.X)

	// omit y3 computation

	// compute line1
	PB(&(line1.r0)).Neg(l1)
	PB(&(line1.r1)).Mul(l1, p1.X)
	PB(&(line1.r1)).Sub(line1.r1, p1.Y)

	// compute lambda2 = -lambda1-2*y1/(x3-x1)
	PB(&n).Double(p1.Y)
	PB(&d).Sub(x3, p1.X)
	PB(&l2).Inverse(d)
	PB(&l2).Mul(l2, n)
	PB(&l2).Add(l2, l1)
	PB(&l2).Neg(l2)

	// compute x4 = lambda2**2-x1-x3
	PB(&x4).Square(l2)
	PB(&x4).Sub(x4, p1.X)
	PB(&x4).Sub(x4, x3)

	// compute y4 = lambda2*(x1 - x4)-y1
	PB(&y4).Sub(p1.X, x4)
	PB(&y4).Mul(l2, y4)
	PB(&y4).Sub(y4, p1.Y)

	PB(&(res.X)).Set(x4)
	PB(&(res.Y)).Set(y4)

	// compute line2
	PB(&(line2.r0)).Neg(l2)
	PB(&(line2.r1)).Mul(l2, p1.X)
	PB(&(line2.r1)).Sub(line2.r1, p1.Y)

	return res, line1, line2
}

func doubleStep[T tower.Tower, PT tower.TowerPt[T, B], B tower.Basis, PB tower.BasisPt[B]](api frontend.API, p1 G2Affine[B, PB]) (G2Affine[B, PB], lineEvaluation[B, PB]) {
	line := newLine[B, PB](api)
	var n, d, l, xr, yr B
	PB(&n).SetAPI(api)
	PB(&d).SetAPI(api)
	PB(&l).SetAPI(api)
	PB(&xr).SetAPI(api)
	PB(&yr).SetAPI(api)

	res, err := NewG2Affine[B, PB](api)
	if err != nil {
		// this is internal step. API is already checked in higher stack
		panic("incompatible api")
	}

	// lambda = 3*p1.x**2/2*p.y
	PB(&n).Square(p1.X)
	PB(&n).MulByFp(n, 3)
	PB(&d).MulByFp(p1.Y, 2)
	PB(&l).Inverse(d)
	PB(&l).Mul(l, n)

	// xr = lambda**2-2*p1.x
	PB(&xr).Square(l)
	PB(&xr).Sub(xr, p1.X)
	PB(&xr).Sub(xr, p1.X)

	// yr = lambda*(p.x-xr)-p.y
	PB(&yr).Sub(p1.X, xr)
	PB(&yr).Mul(l, yr)
	PB(&yr).Sub(yr, p1.Y)

	PB(&(res.X)).Set(xr)
	PB(&(res.Y)).Set(yr)

	PB(&(line.r0)).Neg(l)
	PB(&(line.r1)).Mul(l, p1.X)
	PB(&(line.r1)).Sub(line.r1, p1.Y)

	return res, line
}
