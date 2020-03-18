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

package twistededwards

import "sync"

var edwards CurveParams
var initOnce sync.Once

// GetEdwardsCurve returns the twisted Edwards curve on BN256's Fr
func GetEdwardsCurve() CurveParams {
	initOnce.Do(initEdBN256)
	return edwards
}

func initEdBN256() {

	edwards.A.SetUint64(168700)
	edwards.D.SetUint64(168696)
	edwards.Cofactor.SetUint64(8).FromMont()
	edwards.Order.SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)

	edwards.Base.X.SetString("5299619240641551281634865583518297030282874472190772894086521144482721001553")
	edwards.Base.Y.SetString("16950150798460657717958625567821834550301663161624707787222815936182638968203")
}
