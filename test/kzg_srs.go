/*
Copyright © 2021 ConsenSys Software Inc.

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

package test

import (
	"crypto/rand"
	"math/big"
	"sync"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/internal/utils"

	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	kzg_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/kzg"
	kzg_bls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/kzg"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	kzg_bw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/kzg"
	kzg_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/kzg"
)

// NewKZGSRS uses ccs nb variables and nb constraints to initialize a kzg srs
//
// /!\ warning /!\: this method is here for convenience only: in production, a SRS generated through MPC should be used.
func NewKZGSRS(ccs constraint.ConstraintSystem) (kzg.SRS, error) {

	nbConstraints := ccs.GetNbConstraints()
	sizeSystem := nbConstraints + ccs.GetNbPublicVariables()
	kzgSize := ecc.NextPowerOfTwo(uint64(sizeSystem)) + 3

	return getCachedSRS(ccs, kzgSize)
}

func NewKZGSRSLagrange(ccs constraint.ConstraintSystem) (kzg.SRS, error) {

	nbConstraints := ccs.GetNbConstraints()
	sizeSystem := nbConstraints + ccs.GetNbPublicVariables()
	kzgSize := ecc.NextPowerOfTwo(uint64(sizeSystem))

	return getCachedSRSLagrange(ccs, kzgSize)
}

var (
	lock1, lock2     sync.Mutex
	srsCache         map[ecc.ID]srsCacheEntry
	srsLagrangeCache map[ecc.ID][]srsCacheEntry
)

type srsCacheEntry struct {
	srs  kzg.SRS
	size uint64
}

func init() {
	srsCache = make(map[ecc.ID]srsCacheEntry)
	srsLagrangeCache = make(map[ecc.ID][]srsCacheEntry)
	for _, curve := range gnark.Curves() {
		srsLagrangeCache[curve] = make([]srsCacheEntry, 0)
	}
}
func getCachedSRS(ccs constraint.ConstraintSystem, size uint64) (kzg.SRS, error) {
	lock1.Lock()
	defer lock1.Unlock()

	curveID := utils.FieldToCurve(ccs.Field())

	if entry, ok := srsCache[curveID]; ok && entry.size >= size {
		return entry.srs, nil
	}

	srs, err := newKZGSRS(curveID, size)
	if err != nil {
		return nil, err
	}
	srsCache[curveID] = srsCacheEntry{srs: srs, size: size}
	return srs, nil
}

func getCachedSRSLagrange(ccs constraint.ConstraintSystem, size uint64) (kzg.SRS, error) {
	lock2.Lock()
	defer lock2.Unlock()

	curveID := utils.FieldToCurve(ccs.Field())

	entries := srsLagrangeCache[curveID]
	for _, entry := range entries {
		if entry.size == size {
			return entry.srs, nil
		}
	}

	canonicalSRS, err := getCachedSRS(ccs, size+3)
	if err != nil {
		return nil, err
	}

	var lagrangeSRS kzg.SRS

	switch curveID {
	case ecc.BN254:
		// cast to bn254
		srs := canonicalSRS.(*kzg_bn254.SRS)
		newSRS := &kzg_bn254.SRS{Vk: srs.Vk}
		newSRS.Pk.G1, err = kzg_bn254.ToLagrangeG1(srs.Pk.G1[:size])
		lagrangeSRS = newSRS
	case ecc.BLS12_381:
		// cast to bls12-381
		srs := canonicalSRS.(*kzg_bls12381.SRS)
		newSRS := &kzg_bls12381.SRS{Vk: srs.Vk}
		newSRS.Pk.G1, err = kzg_bls12381.ToLagrangeG1(srs.Pk.G1[:size])
		lagrangeSRS = newSRS
	case ecc.BLS12_377:
		// cast to bls12-377
		srs := canonicalSRS.(*kzg_bls12377.SRS)
		newSRS := &kzg_bls12377.SRS{Vk: srs.Vk}
		newSRS.Pk.G1, err = kzg_bls12377.ToLagrangeG1(srs.Pk.G1[:size])
		lagrangeSRS = newSRS
	case ecc.BW6_761:
		// cast to bw6-761
		srs := canonicalSRS.(*kzg_bw6761.SRS)
		newSRS := &kzg_bw6761.SRS{Vk: srs.Vk}
		newSRS.Pk.G1, err = kzg_bw6761.ToLagrangeG1(srs.Pk.G1[:size])
		lagrangeSRS = newSRS
	case ecc.BLS24_317:
		// cast to bls24-317
		srs := canonicalSRS.(*kzg_bls24317.SRS)
		newSRS := &kzg_bls24317.SRS{Vk: srs.Vk}
		newSRS.Pk.G1, err = kzg_bls24317.ToLagrangeG1(srs.Pk.G1[:size])
		lagrangeSRS = newSRS
	case ecc.BLS24_315:
		// cast to bls24-315
		srs := canonicalSRS.(*kzg_bls24315.SRS)
		newSRS := &kzg_bls24315.SRS{Vk: srs.Vk}
		newSRS.Pk.G1, err = kzg_bls24315.ToLagrangeG1(srs.Pk.G1[:size])
		lagrangeSRS = newSRS
	case ecc.BW6_633:
		// cast to bw6-633
		srs := canonicalSRS.(*kzg_bw6633.SRS)
		newSRS := &kzg_bw6633.SRS{Vk: srs.Vk}
		newSRS.Pk.G1, err = kzg_bw6633.ToLagrangeG1(srs.Pk.G1[:size])
		lagrangeSRS = newSRS
	default:
		panic("unrecognized curve")
	}

	if err != nil {
		return nil, err
	}

	entries = append(entries, srsCacheEntry{srs: lagrangeSRS, size: size})
	srsLagrangeCache[curveID] = entries

	return lagrangeSRS, nil
}

var alpha *big.Int

func init() {
	// for test purposes, we use the same alpha for all SRS we generate.
	var err error
	alpha, err = rand.Int(rand.Reader, ecc.BW6_761.ScalarField())
	if err != nil {
		panic(err)
	}
}

func newKZGSRS(curve ecc.ID, kzgSize uint64) (kzg.SRS, error) {

	beta := new(big.Int).Set(alpha)
	beta.Mod(beta, curve.ScalarField())

	switch curve {
	case ecc.BN254:
		return kzg_bn254.NewSRS(kzgSize, beta)
	case ecc.BLS12_381:
		return kzg_bls12381.NewSRS(kzgSize, beta)
	case ecc.BLS12_377:
		return kzg_bls12377.NewSRS(kzgSize, beta)
	case ecc.BW6_761:
		return kzg_bw6761.NewSRS(kzgSize, beta)
	case ecc.BLS24_317:
		return kzg_bls24317.NewSRS(kzgSize, beta)
	case ecc.BLS24_315:
		return kzg_bls24315.NewSRS(kzgSize, beta)
	case ecc.BW6_633:
		return kzg_bw6633.NewSRS(kzgSize, beta)
	default:
		panic("unrecognized R1CS curve type")
	}
}
