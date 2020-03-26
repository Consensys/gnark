// +build bls377 !bn256,!bls381

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

package fr

import (
	"github.com/consensys/gurvy/bls377/fr"
)

type Element = fr.Element

// TODO also defined in internal/templates/generator
const RootOfUnityStr = "8065159656716812877374967518403273466521432693661810619979959746626482506078"
const MaxOrder = 47
const NbBits = fr.ElementBits
const NbLimbs = fr.ElementLimbs

var FromInterface = fr.FromInterface
var One = fr.One
