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

package gnark_test

import (
	"fmt"
	"sort"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/consensys/gnark/test"
)

func TestIntegrationAPI(t *testing.T) {

	assert := test.NewAssert(t)

	keys := make([]string, 0, len(circuits.Circuits))
	for k := range circuits.Circuits {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i := range keys {

		name := keys[i]
		tData := circuits.Circuits[name]

		// Plonk + FRI is tested only for Mul circuit (otherwise it slows everything down a lot...)
		if name == "mul" {

			assert.Run(func(assert *test.Assert) {
				for i := range tData.ValidAssignments {
					assert.Run(func(assert *test.Assert) {
						assert.ProverSucceeded(tData.Circuit, tData.ValidAssignments[i], test.WithProverOpts(backend.WithHints(tData.HintFunctions...)), test.WithCurves(tData.Curves[0], tData.Curves[1:]...))
					}, fmt.Sprintf("valid-%d", i))
				}

				for i := range tData.InvalidAssignments {
					assert.Run(func(assert *test.Assert) {
						assert.ProverFailed(tData.Circuit, tData.InvalidAssignments[i], test.WithProverOpts(backend.WithHints(tData.HintFunctions...)), test.WithCurves(tData.Curves[0], tData.Curves[1:]...))
					}, fmt.Sprintf("invalid-%d", i))
				}
			}, name)

		} else {

			assert.Run(func(assert *test.Assert) {
				for i := range tData.ValidAssignments {
					assert.Run(func(assert *test.Assert) {
						assert.ProverSucceeded(
							tData.Circuit, tData.ValidAssignments[i],
							test.WithProverOpts(backend.WithHints(tData.HintFunctions...)),
							test.WithCurves(tData.Curves[0], tData.Curves[1:]...),
							test.WithBackends(backend.GROTH16),
							test.WithBackends(backend.PLONK))
					}, fmt.Sprintf("valid-%d", i))
				}

				for i := range tData.InvalidAssignments {
					assert.Run(func(assert *test.Assert) {
						assert.ProverFailed(
							tData.Circuit,
							tData.InvalidAssignments[i],
							test.WithProverOpts(backend.WithHints(tData.HintFunctions...)),
							test.WithCurves(tData.Curves[0], tData.Curves[1:]...),
							test.WithBackends(backend.GROTH16),
							test.WithBackends(backend.PLONK),
						)
					}, fmt.Sprintf("invalid-%d", i))
				}
			}, name)
		}
	}

}
