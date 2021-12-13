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

// Tag contains informations needed to measure and display statistics of a delimited piece of circuit
type Tag struct {
	Name     string
	VID, CID int
}

// Counter contains measurements of useful statistics between two Tag
type Counter struct {
	From, To      Tag
	NbVariables   int
	NbConstraints int
}
