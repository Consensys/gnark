// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package constraint

import (
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
)

func TestWireAliasesSerializationRoundTrip(t *testing.T) {
	for _, test := range []struct {
		name  string
		batch Blueprint
		alias Blueprint
	}{
		{name: "u32", batch: &BlueprintBatchInverse[U32]{}, alias: &BlueprintWireAliases[U32]{}},
		{name: "u64", batch: &BlueprintBatchInverse[U64]{}, alias: &BlueprintWireAliases[U64]{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			system := NewSystem(ecc.BN254.ScalarField(), 4, SystemR1CS)
			genericID := system.AddBlueprint(&BlueprintGenericR1C{})
			system.AddBlueprint(test.batch)
			aliasID := system.AddBlueprint(test.alias)
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
			if got, want := reflect.TypeOf(reconstructed.Blueprints[aliasID]), reflect.TypeOf(test.alias); got != want {
				t.Fatalf("decoded alias blueprint type = %v, want %v", got, want)
			}
		})
	}
}

func TestApplyWireAliasesRewritesLookupHintCalldata(t *testing.T) {
	system := NewSystem(ecc.BN254.ScalarField(), 8, SystemSparseR1CS)
	genericID := system.AddBlueprint(&BlueprintGenericSparseR1C[U64]{})
	aliasID := system.AddBlueprint(&BlueprintWireAliases[U64]{})
	lookup := &BlueprintLookupHint[U64]{}
	lookupID := system.AddBlueprint(lookup)

	entrySrc := uint32(system.AddInternalVariable())
	entryAlias := uint32(system.AddInternalVariable())
	querySrc := uint32(system.AddInternalVariable())
	queryAlias := uint32(system.AddInternalVariable())

	LinearExpression{{CID: CoeffIdOne, VID: entryAlias}}.Compress(&lookup.EntriesCalldata)
	calldata := []uint32{0, 1, 1}
	LinearExpression{{CID: CoeffIdOne, VID: queryAlias}}.Compress(&calldata)
	calldata[0] = uint32(len(calldata))
	system.AddInstruction(lookupID, calldata)

	system.ApplyWireAliases(func(vid uint32) uint32 {
		switch vid {
		case entryAlias:
			return entrySrc
		case queryAlias:
			return querySrc
		default:
			return vid
		}
	}, genericID, aliasID, [][2]uint32{{entryAlias, entrySrc}, {queryAlias, querySrc}})

	if got := lookup.EntriesCalldata[2]; got != entrySrc {
		t.Fatalf("lookup entry calldata wire = %d, want canonical wire %d", got, entrySrc)
	}
	inst := lookupInstruction(t, &system, lookupID)
	if got := inst.Calldata[5]; got != querySrc {
		t.Fatalf("lookup query calldata wire = %d, want canonical wire %d", got, querySrc)
	}
}

func TestApplyWireAliasesResetsLookupHintLevelCache(t *testing.T) {
	system := NewSystem(ecc.BN254.ScalarField(), 8, SystemSparseR1CS)
	genericID := system.AddBlueprint(&BlueprintGenericSparseR1C[U64]{})
	aliasID := system.AddBlueprint(&BlueprintWireAliases[U64]{})
	lookup := &BlueprintLookupHint[U64]{
		maxLevelPosition: 99,
		maxLevelOffset:   99,
	}
	lookupID := system.AddBlueprint(lookup)

	entrySrc := uint32(system.AddInternalVariable())
	entryAlias := uint32(system.AddInternalVariable())
	query := uint32(system.AddInternalVariable())

	LinearExpression{{CID: CoeffIdOne, VID: entryAlias}}.Compress(&lookup.EntriesCalldata)
	calldata := []uint32{0, 1, 1}
	LinearExpression{{CID: CoeffIdOne, VID: query}}.Compress(&calldata)
	calldata[0] = uint32(len(calldata))
	system.AddInstruction(lookupID, calldata)

	system.ApplyWireAliases(func(vid uint32) uint32 {
		if vid == entryAlias {
			return entrySrc
		}
		return vid
	}, genericID, aliasID, [][2]uint32{{entryAlias, entrySrc}})

	if lookup.maxLevelPosition != 1 {
		t.Fatalf("lookup maxLevelPosition = %d, want recomputed position 1", lookup.maxLevelPosition)
	}
	if lookup.maxLevelOffset != len(lookup.EntriesCalldata) {
		t.Fatalf("lookup maxLevelOffset = %d, want %d", lookup.maxLevelOffset, len(lookup.EntriesCalldata))
	}
}

func TestApplyWireAliasesRewritesLogAndDebugExpressions(t *testing.T) {
	system := NewSystem(ecc.BN254.ScalarField(), 4, SystemR1CS)
	genericID := system.AddBlueprint(&BlueprintGenericR1C{})
	aliasID := system.AddBlueprint(&BlueprintWireAliases[U64]{})
	source := uint32(system.AddInternalVariable())
	alias := uint32(system.AddInternalVariable())

	system.Logs = []LogEntry{{ToResolve: []LinearExpression{{{CID: CoeffIdOne, VID: alias}}}}}
	system.DebugInfo = []LogEntry{{ToResolve: []LinearExpression{{{CID: CoeffIdOne, VID: alias}}}}}
	system.ApplyWireAliases(func(vid uint32) uint32 {
		if vid == alias {
			return source
		}
		return vid
	}, genericID, aliasID, [][2]uint32{{alias, source}})

	if got := system.Logs[0].ToResolve[0][0].VID; got != source {
		t.Fatalf("log wire = %d, want canonical wire %d", got, source)
	}
	if got := system.DebugInfo[0].ToResolve[0][0].VID; got != source {
		t.Fatalf("debug wire = %d, want canonical wire %d", got, source)
	}
}

func lookupInstruction(t *testing.T, system *System, lookupID BlueprintID) Instruction {
	t.Helper()
	for _, pi := range system.Instructions {
		if pi.BlueprintID == lookupID {
			return pi.Unpack(system)
		}
	}
	t.Fatalf("lookup instruction %d not found", lookupID)
	return Instruction{}
}
