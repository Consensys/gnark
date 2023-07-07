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

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bw6761"
	"github.com/consensys/gnark/std/math/emulated"
)

type Pairing struct {
	*fields_bw6761.Ext6
	curveF emulated.Field[emulated.BW6761Fp]
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	return &Pairing{
		Ext6: fields_bw6761.NewExt6(ba),
	}, nil
}

// GT target group of the pairing
type GT = fields_bw6761.E6

// FinalExponentiation computes the exponentiation (∏ᵢ zᵢ)ᵈ
// where d = (p^6-1)/r = (p^6-1)/Φ_6(p) ⋅ Φ_6(p)/r = (p^3-1)(p+1)(p^2 - p +1)/r
// we use instead d=s ⋅ (p^3-1)(p+1)(p^2 - p +1)/r
// where s is the cofactor 12(x_0+1) (El Housni and Guillevic)
func (pr Pairing) FinalExponentiation(z *GT, _z ...*GT) *GT {

	result := pr.Set(z)

	for _, a := range _z {
		result = pr.Mul(result, a)
	}

	// Easy part
	// (p^3-1)(p+1)
	buf := pr.Conjugate(result)
	result = pr.Inverse(result)
	buf = pr.Mul(buf, result)
	result = pr.Frobenius(buf)
	result = pr.Mul(result, buf)

	// Hard part (up to permutation)
	// El Housni and Guillevic
	// https://eprint.iacr.org/2020/351.pdf
	m1 := pr.Expt(result)
	_m1 := pr.Conjugate(m1)
	m2 := pr.Expt(m1)
	_m2 := pr.Conjugate(m2)
	m3 := pr.Expt(m2)
	f0 := pr.Frobenius(result)
	f0 = pr.Mul(f0, result)
	f0 = pr.Mul(f0, m2)
	m2 = pr.CyclotomicSquare(_m1)
	f0 = pr.Mul(f0, m2)
	f0_36 := pr.CyclotomicSquare(f0)
	f0_36 = pr.CyclotomicSquare(f0_36)
	f0_36 = pr.CyclotomicSquare(f0_36)
	f0_36 = pr.Mul(f0_36, f0)
	f0_36 = pr.CyclotomicSquare(f0_36)
	f0_36 = pr.CyclotomicSquare(f0_36)
	g0 := pr.Mul(result, m1)
	g0 = pr.Frobenius(g0)
	g0 = pr.Mul(g0, m3)
	g0 = pr.Mul(g0, _m2)
	g0 = pr.Mul(g0, _m1)
	g1 := pr.Expt(g0)
	_g1 := pr.Conjugate(g1)
	g2 := pr.Expt(g1)
	g3 := pr.Expt(g2)
	_g3 := pr.Conjugate(g3)
	g4 := pr.Expt(g3)
	_g4 := pr.Conjugate(g4)
	g5 := pr.Expt(g4)
	_g5 := pr.Conjugate(g5)
	g6 := pr.Expt(g5)
	gA := pr.Mul(g3, _g5)
	gA = pr.CyclotomicSquare(gA)
	gA = pr.Mul(gA, g6)
	gA = pr.Mul(gA, g1)
	gA = pr.Mul(gA, g0)
	g034 := pr.Mul(g0, g3)
	g034 = pr.Mul(g034, _g4)
	gB := pr.CyclotomicSquare(g034)
	gB = pr.Mul(gB, g034)
	gB = pr.Mul(gB, g5)
	gB = pr.Mul(gB, _g1)
	_g1g2 := pr.Mul(_g1, g2)
	gC := pr.Mul(_g3, _g1g2)
	gC = pr.CyclotomicSquare(gC)
	gC = pr.Mul(gC, _g1g2)
	gC = pr.Mul(gC, g0)
	gC = pr.CyclotomicSquare(gC)
	gC = pr.Mul(gC, g2)
	gC = pr.Mul(gC, g0)
	gC = pr.Mul(gC, g4)

	// ht, hy = 13, 9
	// c1 = ht**2+3*hy**2 = 412
	h1 := pr.Expc1(gA)
	// c2 = ht+hy = 22
	h2 := pr.Expc2(gB)
	h2g2C := pr.CyclotomicSquare(gC)
	h2g2C = pr.Mul(h2g2C, h2)
	h4 := pr.CyclotomicSquare(h2g2C)
	h4 = pr.Mul(h4, h2g2C)
	h4 = pr.CyclotomicSquare(h4)
	result = pr.Mul(h1, h4)
	result = pr.Mul(result, f0_36)

	return result
}
