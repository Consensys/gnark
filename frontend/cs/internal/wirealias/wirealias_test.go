// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package wirealias

import (
	"reflect"
	"testing"
)

func TestSetAliasesOnlyInternalWires(t *testing.T) {
	var aliases Set
	aliases.MarkInternal(8)

	if aliases.Union(7, 8) {
		t.Fatal("non-internal wires must not be aliased")
	}
	if aliases.HasAliases() {
		t.Fatal("rejected union must not mark set as aliased")
	}

	aliases.MarkInternal(7)
	if !aliases.Union(7, 8) {
		t.Fatal("internal wires should be aliased")
	}
	if got := aliases.Rep(8); got != 7 {
		t.Fatalf("expected lower wire representative 7, got %d", got)
	}
	if got, want := aliases.Mappings(), [][2]int{{8, 7}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected mappings: got %v want %v", got, want)
	}
}

func TestSetLateNoAliasBlocksFutureUnion(t *testing.T) {
	var aliases Set
	for _, wire := range []int{2, 3, 4} {
		aliases.MarkInternal(wire)
	}

	if !aliases.Union(3, 4) {
		t.Fatal("initial internal alias should be accepted")
	}
	aliases.MarkNoAlias(4)

	if aliases.Union(2, 3) {
		t.Fatal("no-alias class must reject later unions")
	}
	if got := aliases.Rep(4); got != 3 {
		t.Fatalf("existing alias should remain canonicalized, got representative %d", got)
	}
	if got, want := aliases.Mappings(), [][2]int{{4, 3}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected mappings: got %v want %v", got, want)
	}
}
