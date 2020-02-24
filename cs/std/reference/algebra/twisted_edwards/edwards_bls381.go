// +build bls381

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

package twistededwards

import "sync"

var edwards CurveParams
var initOnce sync.Once

// GetEdwardsCurve returns the twisted Edwards curve on BLS381's Fr
func GetEdwardsCurve() CurveParams {
	initOnce.Do(initEdBLS381)
	return edwards
}

func initEdBLS381() {

	edwards.A.SetString("52435875175126190479447740508185965837690552500527637822603658699938581184512") // -1
	edwards.D.SetString("19257038036680949359750312669786877991949435402254120286184196891950884077233") // -(10240/10241)
	edwards.Cofactor.SetUint64(8).FromMont()
	edwards.Order.SetString("52435875175126190479447740508185965837647370126978538250922873299137466033592", 10)

	edwards.Base.X.SetString("23426137002068529236790192115758361610982344002369094106619281483467893291614")
	edwards.Base.Y.SetString("39325435222430376843701388596190331198052476467368316772266670064146548432123")
}
