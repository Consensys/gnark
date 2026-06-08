// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package constraint

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
)

func TestWireAliasesSerializationRoundTrip(t *testing.T) {
	system := NewSystem(ecc.BN254.ScalarField(), 4, SystemR1CS)
	genericID := system.AddBlueprint(&BlueprintGenericR1C{})
	system.AddBlueprint(&BlueprintBatchInverse[U64]{})
	aliasID := system.AddBlueprint(&BlueprintWireAliases[U64]{})
	system.AddPublicVariable("1")
	a := uint32(system.AddSecretVariable("a"))
	bb := uint32(system.AddSecretVariable("b"))
	c := uint32(system.AddSecretVariable("c"))
	d := uint32(system.AddSecretVariable("d"))
	x := uint32(system.AddInternalVariable())
	y := uint32(system.AddInternalVariable())

	system.AddR1C(R1C{
		L: LinearExpression{{CID: CoeffIdOne, VID: a}},
		R: LinearExpression{{CID: CoeffIdOne, VID: bb}},
		O: LinearExpression{{CID: CoeffIdOne, VID: x}},
	}, genericID)
	system.AddR1C(R1C{
		L: LinearExpression{{CID: CoeffIdOne, VID: c}},
		R: LinearExpression{{CID: CoeffIdOne, VID: d}},
		O: LinearExpression{{CID: CoeffIdOne, VID: y}},
	}, genericID)

	system.ApplyWireAliases(func(vid uint32) uint32 {
		if vid == y {
			return x
		}
		return vid
	}, genericID, aliasID, [][2]uint32{{y, x}})

	b, err := system.ToBytes()
	if err != nil {
		t.Fatal(err)
	}

	var reconstructed System
	if _, err := reconstructed.FromBytes(b); err != nil {
		t.Fatal(err)
	}
}
