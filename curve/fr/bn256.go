// +build bn256

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

import "github.com/consensys/gurvy/bn256/fr"

type Element = fr.Element

// TODO also defined in internal/templates/generator
const RootOfUnityStr = "19103219067921713944291392827692070036145651957329286315305642004821462161904"
const MaxOrder = 28
const NbBits = fr.ElementBits
const NbLimbs = fr.ElementLimbs

var FromInterface = fr.FromInterface
var One = fr.One
