/*
Copyright © 2022 ConsenSys Software Inc.

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

package schema

import "github.com/consensys/gnark/internal/backend/compiled"

// Field represent a schema Field and is analogous to reflect.StructField (but simplified)
type Field struct {
	Name       string
	NameTag    string
	Visibility compiled.Visibility
	Type       FieldType
	SubFields  []Field // will be set only if it's a struct, or an array of struct
	ArraySize  int
}

// FieldType represents the type a field is allowed to have in a gnark Schema
type FieldType uint8

const (
	Leaf FieldType = iota
	Array
	Struct
)
