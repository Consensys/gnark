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
	"os"
	"testing"

	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/consensys/gnark/test"
)

func TestIntegrationAPI(t *testing.T) {

	assert := test.NewAssert(t)

	// create temporary dir for integration test
	parentDir := "./integration_test"
	os.RemoveAll(parentDir)
	defer os.RemoveAll(parentDir)
	if err := os.MkdirAll(parentDir, 0700); err != nil {
		t.Fatal(err)
	}

	for name, tData := range circuits.Circuits {
		t.Log(name)
		for _, w := range tData.ValidWitnesses {
			assert.ProverSucceeded(tData.Circuit, w)
		}

		for _, w := range tData.InvalidWitnesses {
			assert.ProverFailed(tData.Circuit, w)
		}

	}

}
