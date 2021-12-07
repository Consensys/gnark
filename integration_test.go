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

package gnark

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
		assert.Run(func(assert *test.Assert) {
			for i := range tData.ValidWitnesses {
				assert.Run(func(assert *test.Assert) {
					assert.ProverSucceeded(tData.Circuit, tData.ValidWitnesses[i], test.WithProverOpts(backend.WithHints(tData.HintFunctions...)), test.WithCurves(tData.Curves[0], tData.Curves[1:]...))
				}, fmt.Sprintf("valid-%d", i))
			}

			for i := range tData.InvalidWitnesses {
				assert.Run(func(assert *test.Assert) {
					assert.ProverFailed(tData.Circuit, tData.InvalidWitnesses[i], test.WithProverOpts(backend.WithHints(tData.HintFunctions...)), test.WithCurves(tData.Curves[0], tData.Curves[1:]...))
				}, fmt.Sprintf("invalid-%d", i))
			}
		}, name)
	}

}
