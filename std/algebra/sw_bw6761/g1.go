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

package sw_bw6761

import "github.com/consensys/gnark/frontend"

// G1Affine point in affine coordinates
type G1Affine struct {
	X, Y frontend.Variable
}

// G1Jac is a point with fp.Element coordinates
type G1Jac struct {
	X, Y, Z frontend.Variable
}

// g1Proj point in projective coordinates
type g1Proj struct {
	x, y, z frontend.Variable
}

// Neg computes -G
func (p *G1Affine) Neg(api frontend.API, a G1Affine) *G1Affine {
	p.X = a.X
	p.Y = api.Neg(a.Y)
	return p
}

// Set sets p to the provided point
func (p *G1Jac) Set(a G1Jac) *G1Jac {
	p.X, p.Y, p.Z = a.X, a.Y, a.Z
	return p
}

// Set sets p to the provided point
func (p *g1Proj) Set(a g1Proj) *g1Proj {
	p.x, p.y, p.z = a.x, a.y, a.z
	return p
}

// Neg computes -G
func (p *g1Proj) Neg(api frontend.API, a g1Proj) *g1Proj {
	p.Set(a)
	p.y = api.Neg(a.y)
	return p
}

// FromAffine sets p = Q, p in homogenous projective, Q in affine
func (p *g1Proj) FromAffine(api frontend.API, Q G1Affine) *g1Proj {
	// TODO
	//flag := api.And(api.IsZero(Q.X), api.IsZero(Q.Y))
	//p.z = api.Select(flag, 0, 1)
	//p.x = api.Select(flag, 1, Q.X)
	//p.y = api.Select(flag, 1, Q.Y)
	p.z = 1
	p.x = Q.X
	p.y = Q.Y
	return p
}

// BatchProjectiveToAffineG1 converts points in Projective coordinates to Affine coordinates
// performing a single field inversion (Montgomery batch inversion trick).
func BatchProjectiveToAffineG1(api frontend.API, points []g1Proj) []G1Affine {
	result := make([]G1Affine, len(points))
	//zeroes := make([]bool, len(points))
	var accumulator frontend.Variable
	accumulator = 1

	// batch invert all points[].Z coordinates with Montgomery batch inversion trick
	// (stores points[].Z^-1 in result[i].X to avoid allocating a slice of fr.Elements)
	for i := 0; i < len(points); i++ {
		//if points[i].z.IsZero() {
		//	zeroes[i] = true
		//	continue
		//}
		result[i].X = accumulator
		accumulator = api.Mul(accumulator, points[i].z)
	}

	var accInverse frontend.Variable
	accInverse = api.Inverse(accumulator)

	for i := len(points) - 1; i >= 0; i-- {
		//if zeroes[i] {
		//	// do nothing, (X=0, Y=0) is infinity point in affine
		//	continue
		//}
		result[i].X = api.Mul(result[i].X, accInverse)
		accInverse = api.Mul(accInverse, points[i].z)
	}

	// batch convert to affine.
	for i := 0; i < len(points); i++ {
		//if zeroes[i] {
		//	// do nothing, (X=0, Y=0) is infinity point in affine
		//	continue
		//}
		a := result[i].X
		result[i].X = api.Mul(points[i].x, a)
		result[i].Y = api.Mul(points[i].y, a)
	}
	return result
}
