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

package frontend

// wire is analogous to a circuit's physical Wire
// each constraint (ie gate) will have a single output Wire
// when the circuit is instantiated and fed an input
// each Wire will have a Value enabling the solver to determine a solution vector
// to the rank 1 constraint system
type wire struct {
	// note that theses are prefixed "final" because these IDs are computed in
	// cs.ToR1CS when the wires and constraints are ordered
	finalWireID       int
	finalConstraintID int // ID of the constraint from which the wire is computed (for an input it's -1)
}

// func (w wire) String() string {
// 	res := "unimplemeted"
// 	// if w.Name != "" {
// 	// 	res = res + w.Name
// 	// 	if w.WireIDOrdering != -1 {
// 	// 		res = res + " (wire_" + strconv.Itoa(int(w.WireIDOrdering)) + ")"
// 	// 	}
// 	// } else {
// 	res = "wire_" + strconv.Itoa(int(w.wIDOrdered))
// 	// }
// 	res = res + " (c " + strconv.Itoa(int(w.cIDOrdered)) + ")"
// 	return res
// }
