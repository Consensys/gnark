/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sw_bls24315

import (
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls24315"
)

// lineEvaluation represents a sparse Fp12 Elmt (result of the line evaluation)
// line: 1 + R0(x/y) + R1(1/y) = 0 instead of R0'*y + R1'*x + R2' = 0 This
// makes the multiplication by lines (MulBy014)
type lineEvaluation struct {
	R0, R1 fields_bls24315.E4
}
type lineEvaluations [2][len(loopCounter) - 1]*lineEvaluation

func precomputeLines(Q bls24315.G2Affine) lineEvaluations {
	var cLines lineEvaluations
	nLines := bls24315.PrecomputeLines(Q)
	for j := range cLines[0] {
		cLines[0][j] = new(lineEvaluation)
		cLines[1][j] = new(lineEvaluation)
		cLines[0][j].R0.Assign(&nLines[0][j].R0)
		cLines[0][j].R1.Assign(&nLines[0][j].R1)
		cLines[1][j].R0.Assign(&nLines[1][j].R0)
		cLines[1][j].R1.Assign(&nLines[1][j].R1)
	}
	return cLines
}

func computeLines(api frontend.API, Q g2AffP) *lineEvaluations {

	var cLines lineEvaluations
	Qacc := Q
	QNeg := &g2AffP{}
	QNeg.Neg(api, Q)
	n := len(loopCounter)
	Qacc, cLines[0][n-2] = doubleStep(api, &Qacc)
	cLines[1][n-3] = lineCompute(api, &Qacc, QNeg)
	Qacc, cLines[0][n-3] = addStep(api, &Qacc, &Q)

	for i := n - 4; i >= 1; i-- {
		switch loopCounter[i] {
		case 0:
			Qacc, cLines[0][i] = doubleStep(api, &Qacc)
		case 1:
			Qacc, cLines[0][i], cLines[1][i] = doubleAndAddStep(api, &Qacc, &Q)
		case -1:
			Qacc, cLines[0][i], cLines[1][i] = doubleAndAddStep(api, &Qacc, QNeg)
		default:
			return &lineEvaluations{}
		}
	}
	cLines[0][0], cLines[1][0] = linesCompute(api, &Qacc, QNeg)
	return &cLines
}
