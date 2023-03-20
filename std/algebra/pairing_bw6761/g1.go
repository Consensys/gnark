/*
 *
 * Copyright © 2020 ConsenSys
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * /
 */

package pairing_bw6761

import (
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/std/math/emulated"
)

type G1Affine struct {
	X, Y baseField
}

func NewG1Affine(a bw6761.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[emulated.BW6761Fp](a.X),
		Y: emulated.ValueOf[emulated.BW6761Fp](a.Y),
	}
}

// Neg computes -G
func (p *G1Affine) Neg(pr *Pairing, a *G1Affine) *G1Affine {
	p.X = a.X
	p.Y = *pr.fp.Neg(&a.Y)
	return p
}

// g1Proj point in projective coordinates
type g1Proj struct {
	x, y, z baseField
}

// Set sets p to the provided point
func (p *g1Proj) Set(a *g1Proj) *g1Proj {
	p.x, p.y, p.z = a.x, a.y, a.z
	return p
}

// Neg computes -G
func (p *g1Proj) Neg(pr *Pairing, a *g1Proj) *g1Proj {
	p.Set(a)
	p.y = *pr.fp.Neg(&a.y)
	return p
}

// FromAffine sets p = Q, p in homogenous projective, Q in affine
func (p *g1Proj) FromAffine(pr *Pairing, Q *G1Affine) *g1Proj {
	// TODO
	//flag := api.And(api.IsZero(Q.X), api.IsZero(Q.Y))
	//p.z = api.Select(flag, 0, 1)
	//p.x = api.Select(flag, 1, Q.X)
	//p.y = api.Select(flag, 1, Q.Y)
	p.z = *pr.fp.One()
	p.x = Q.X
	p.y = Q.Y
	return p
}

// BatchProjectiveToAffineG1 converts points in Projective coordinates to Affine coordinates
// performing a single field inversion (Montgomery batch inversion trick).
func BatchProjectiveToAffineG1(pr *Pairing, points []g1Proj) []G1Affine {
	result := make([]G1Affine, len(points))
	//zeroes := make([]bool, len(points))
	accumulator := pr.fp.One()

	// batch invert all points[].Z coordinates with Montgomery batch inversion trick
	// (stores points[].Z^-1 in result[i].X to avoid allocating a slice of fr.Elements)
	for i := 0; i < len(points); i++ {
		//if points[i].z.IsZero() {
		//	zeroes[i] = true
		//	continue
		//}
		result[i].X = *accumulator
		accumulator = pr.fp.MulMod(accumulator, &points[i].z)
	}

	accInverse := pr.fp.Inverse(accumulator)

	for i := len(points) - 1; i >= 0; i-- {
		//if zeroes[i] {
		//	// do nothing, (X=0, Y=0) is infinity point in affine
		//	continue
		//}
		result[i].X = *pr.fp.MulMod(&result[i].X, accInverse)
		accInverse = pr.fp.MulMod(accInverse, &points[i].z)
	}

	// batch convert to affine.
	for i := 0; i < len(points); i++ {
		//if zeroes[i] {
		//	// do nothing, (X=0, Y=0) is infinity point in affine
		//	continue
		//}
		a := result[i].X
		result[i].X = *pr.fp.MulMod(&points[i].x, &a)
		result[i].Y = *pr.fp.MulMod(&points[i].y, &a)
	}
	return result
}
