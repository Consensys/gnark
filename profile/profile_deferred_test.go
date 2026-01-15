//go:build !windows

package profile_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/math/emulated"
)

// EmulatedCircuit uses emulated field operations which generate deferred constraints
type EmulatedCircuit struct {
	A, B emulated.Element[emulated.Secp256k1Fp]
}

func (circuit *EmulatedCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[emulated.Secp256k1Fp](api)
	if err != nil {
		return err
	}
	// This multiplication will generate deferred constraints for the multiplication check
	c := f.Mul(&circuit.A, &circuit.B)
	// Add a simple constraint to use c
	f.AssertIsEqual(c, c)
	return nil
}

func TestDeferredProfile(t *testing.T) {
	p := profile.Start(profile.WithPath("./test_gnark.pprof"))
	_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &EmulatedCircuit{})
	p.Stop()

	if err != nil {
		t.Fatal(err)
	}

	totalConstraints := p.NbConstraints()
	deferredConstraints := p.NbDeferredConstraints()

	t.Logf("Total constraints: %d", totalConstraints)
	t.Logf("Deferred constraints: %d", deferredConstraints)

	// The emulated field generates deferred constraints for multiplication checks
	if deferredConstraints == 0 {
		t.Error("Expected some deferred constraints from emulated field operations")
	}

	// Check that deferred constraints are properly attributed
	topDeferred := p.TopDeferred()
	t.Logf("Deferred profile:\n%s", topDeferred)

	// The deferred constraints should be attributed to something related to the circuit
	// or the emulated field operations, not just internal functions
	if topDeferred != "No deferred constraints recorded" {
		// Check that we have some attribution in the deferred profile
		if !strings.Contains(topDeferred, "emulated") && !strings.Contains(topDeferred, "Define") {
			t.Logf("Warning: deferred constraints may not be properly attributed to source")
		}
	}

	// Regular profile should also have constraints
	top := p.Top()
	t.Logf("Regular profile:\n%s", top)
}

func Example_deferredConstraints() {
	p := profile.Start(profile.WithNoOutput())
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &EmulatedCircuit{})
	p.Stop()

	fmt.Printf("Total constraints: %d\n", p.NbConstraints())
	fmt.Printf("Has deferred: %v\n", p.NbDeferredConstraints() > 0)
	// Output:
	// Total constraints: 1408
	// Has deferred: true
}
