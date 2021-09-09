// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compiled

import (
	"html/template"
	"io"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
)

// R1CS decsribes a set of R1CS constraint
type R1CS struct {
	// Wires
	NbInternalVariables  int
	NbPublicVariables    int // includes ONE wire
	NbSecretVariables    int
	Logs                 []LogEntry
	DebugInfoComputation []LogEntry
	DebugInfoAssertion   []LogEntry

	// Constraints
	NbConstraints   int // total number of constraints
	NbCOConstraints int // number of constraints that need to be solved, the first of the Constraints slice
	Constraints     []R1C

	// Hints
	Hints []Hint
}

// GetNbConstraints returns the number of constraints
func (r1cs *R1CS) GetNbConstraints() int {
	return r1cs.NbConstraints
}

// GetNbVariables return number of internal, secret and public variables
func (r1cs *R1CS) GetNbVariables() (internal, secret, public int) {
	internal = r1cs.NbInternalVariables
	secret = r1cs.NbSecretVariables
	public = r1cs.NbPublicVariables
	return
}

// GetNbCoefficients return the number of unique coefficients needed in the R1CS
func (r1cs *R1CS) GetNbCoefficients() int {
	panic("not implemented")
}

// CurveID returns ecc.UNKNOWN as this is a untyped R1CS using big.Int
func (r1cs *R1CS) CurveID() ecc.ID {
	return ecc.UNKNOWN
}

// FrSize panics
func (r1cs *R1CS) FrSize() int {
	panic("not implemented")
}

// WriteTo panics (can't serialize untyped R1CS)
func (r1cs *R1CS) WriteTo(w io.Writer) (n int64, err error) {
	panic("not implemented")
}

// ReadFrom panics (can't deserialize untyped R1CS)
func (r1cs *R1CS) ReadFrom(r io.Reader) (n int64, err error) {
	panic("not implemented")
}

// SetLoggerOutput replace existing logger output with provided one
// default uses os.Stdout
// if nil is provided, logs are not printed
func (r1cs *R1CS) SetLoggerOutput(w io.Writer) {
	panic("not implemented")
}

// ToHTML returns an HTML human-readable representation of the constraint system
func (r1cs *R1CS) ToHTML(w io.Writer, coeffs []big.Int) error {
	t, err := template.New("r1cs.html").Parse(tmpl)
	if err != nil {
		return err
	}

	return t.Execute(os.Stdout, r1cs)
}

const tmpl = `
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-F3w7mX95PdgyTmZZMECAngseQB83DfGTowi0iMjiWaeVhAn4FJkqJByhZMI3AhiU" crossorigin="anonymous">
    <title>R1CS</title>

    <style>
        .coeff {text-align:right;}
    </style>
  </head>
  <body>
    <h1>R1CS</h1>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.1/dist/js/bootstrap.bundle.min.js" integrity="sha384-/bQdsTh/da6pkI1MST/rWKFNjaCP5gBSY4sEBT38Q/9RBh9AH40zEOg7Hlq2THRZ" crossorigin="anonymous"></script>

<table class="table table-bordered">
  <thead>
    <tr>
      <th scope="col">#</th>
      <th scope="col" colspan="2">L</th>
      <th scope="col" colspan="2">R</th>
      <th scope="col" colspan="2">O</th>
    </tr>
  </thead>
  <tbody>
    {{- range $c := .Constraints}}
    <tr>
      <th scope="row">0</th>
      <!---  L  -->
      <td class="coeff table-light">coeff</td>
      <td class="variable">variable</td>
      <!---  R  -->
      <td class="coeff table-light">coeff</td>
      <td class="variable">variable</td>
      <!---  O  -->
      <td class="coeff table-light">coeff</td>
      <td class="variable">variable</td>
    </tr>
    {{- end }}
  </tbody>
</table>
  </body>
</html>
`
