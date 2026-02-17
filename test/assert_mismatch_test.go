package test

import (
	"sync"
	"testing"
)

func TestDeepEqualMismatch_BasicTypes(t *testing.T) {
	// Identical ints
	path, _, _ := deepEqualMismatch(1, 1)
	if path != "" {
		t.Errorf("expected no mismatch for identical ints, got path: %s", path)
	}

	// Different ints
	path, a, b := deepEqualMismatch(1, 2)
	if path == "" {
		t.Error("expected mismatch for different ints")
	} else {
		t.Logf("int mismatch: path=%s, a=%s, b=%s", path, a, b)
	}
}

func TestDeepEqualMismatch_Structs(t *testing.T) {
	type Simple struct {
		X int
		Y string
	}

	// Identical structs
	path, _, _ := deepEqualMismatch(Simple{1, "a"}, Simple{1, "a"})
	if path != "" {
		t.Errorf("expected no mismatch for identical structs, got path: %s", path)
	}

	// Different field
	path, a, b := deepEqualMismatch(Simple{1, "a"}, Simple{2, "a"})
	if path == "" {
		t.Error("expected mismatch for different structs")
	} else {
		t.Logf("struct mismatch: path=%s, a=%s, b=%s", path, a, b)
	}
}

func TestDeepEqualMismatch_Pointers(t *testing.T) {
	type Simple struct {
		X int
	}

	a := &Simple{1}
	b := &Simple{1}
	c := &Simple{2}

	// Identical pointed-to values
	path, _, _ := deepEqualMismatch(a, b)
	if path != "" {
		t.Errorf("expected no mismatch for identical pointer targets, got path: %s", path)
	}

	// Different pointed-to values
	path, av, bv := deepEqualMismatch(a, c)
	if path == "" {
		t.Error("expected mismatch for different pointer targets")
	} else {
		t.Logf("pointer mismatch: path=%s, a=%s, b=%s", path, av, bv)
	}
}

func TestDeepEqualMismatch_UnexportedFields(t *testing.T) {
	type withUnexported struct {
		Public  int
		private int
	}

	a := &withUnexported{Public: 1, private: 10}
	b := &withUnexported{Public: 1, private: 10}
	c := &withUnexported{Public: 1, private: 20}

	// Identical (including unexported)
	path, _, _ := deepEqualMismatch(a, b)
	if path != "" {
		t.Errorf("expected no mismatch, got path: %s", path)
	}

	// Different unexported field
	path, av, bv := deepEqualMismatch(a, c)
	if path == "" {
		t.Error("expected mismatch for different unexported field")
	} else {
		t.Logf("unexported mismatch: path=%s, a=%s, b=%s", path, av, bv)
	}
}

func TestDeepEqualMismatch_SyncPool(t *testing.T) {
	type WithPool struct {
		Name string
		Pool sync.Pool
	}

	a := &WithPool{Name: "test"}
	b := &WithPool{Name: "test"}

	// Set different New functions
	a.Pool.New = func() interface{} { return "a" }
	b.Pool.New = func() interface{} { return "b" }

	path, av, bv := deepEqualMismatch(a, b)
	if path == "" {
		t.Error("expected mismatch for different sync.Pool.New functions")
	} else {
		t.Logf("sync.Pool mismatch: path=%s, a=%s, b=%s", path, av, bv)
	}
}

func TestDeepEqualMismatch_Slices(t *testing.T) {
	type Item struct {
		Value int
	}

	a := []*Item{{1}, {2}}
	b := []*Item{{1}, {2}}
	c := []*Item{{1}, {3}}

	// Identical slices
	path, _, _ := deepEqualMismatch(a, b)
	if path != "" {
		t.Errorf("expected no mismatch, got path: %s", path)
	}

	// Different element
	path, av, bv := deepEqualMismatch(a, c)
	if path == "" {
		t.Error("expected mismatch for different slice element")
	} else {
		t.Logf("slice mismatch: path=%s, a=%s, b=%s", path, av, bv)
	}
}

func TestDeepEqualMismatch_Interface(t *testing.T) {
	type Container struct {
		Data interface{}
	}

	a := &Container{Data: 1}
	b := &Container{Data: 1}
	c := &Container{Data: 2}

	// Identical
	path, _, _ := deepEqualMismatch(a, b)
	if path != "" {
		t.Errorf("expected no mismatch, got path: %s", path)
	}

	// Different
	path, av, bv := deepEqualMismatch(a, c)
	if path == "" {
		t.Error("expected mismatch")
	} else {
		t.Logf("interface mismatch: path=%s, a=%s, b=%s", path, av, bv)
	}
}

// Blueprint is a simple interface mimicking constraint.Blueprint
type Blueprint interface {
	Name() string
}

// BlueprintWithPool mimics BlueprintSolve with sync.Pool
type BlueprintWithPool struct {
	Data string
	pool sync.Pool
}

func (b *BlueprintWithPool) Name() string { return b.Data }

// System mimics constraint.System with a slice of Blueprint interfaces
type System struct {
	Blueprints []Blueprint
}

func TestDeepEqualMismatch_BlueprintLike(t *testing.T) {
	// Create two systems with blueprints that have different pool.New functions
	bp1 := &BlueprintWithPool{Data: "test"}
	bp1.pool.New = func() interface{} { return "a" }

	bp2 := &BlueprintWithPool{Data: "test"}
	bp2.pool.New = func() interface{} { return "b" }

	sys1 := &System{Blueprints: []Blueprint{bp1}}
	sys2 := &System{Blueprints: []Blueprint{bp2}}

	path, av, bv := deepEqualMismatch(sys1, sys2)
	if path == "" {
		t.Error("expected mismatch for systems with different blueprint pool.New")
	} else {
		t.Logf("system mismatch: path=%s, a=%s, b=%s", path, av, bv)
	}
}
