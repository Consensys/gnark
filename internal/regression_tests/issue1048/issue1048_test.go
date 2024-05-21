package issue1048

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

var (
	h1Unlocker chan struct{}
	h2Unlocker chan struct{}
)

func HintControllable1(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	time.Sleep(100 * time.Millisecond)
	for range h1Unlocker {
	}
	// add some sleep to this test to ensure that if there is parallelism, this
	// hint returns second.
	return fmt.Errorf("hint controllable 1")
}

func HintControllable2(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	for range h2Unlocker {
	}
	return fmt.Errorf("hint controllable 2")
}

type Circuit struct {
	A frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	_, err := api.Compiler().NewHint(HintControllable1, 1, c.A)
	if err != nil {
		return err
	}
	// the solver groups currently instructions into group of 50. So there needs to be at least 50 instructions.
	for i := 0; i < 50; i++ {
		api.AssertIsEqual(c.A, c.A)
	}
	_, err = api.Compiler().NewHint(HintControllable2, 1, c.A)
	if err != nil {
		return err
	}

	return nil
}

// TestTwoTasksOrder tests that when we run multiple tasks, then indeed they are
// run in parallel. And if there is one task, then it indeed is one task (with
// high probability).
func TestTwoTasksOrder(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit Circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	assignment := Circuit{A: 10}
	wit, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	// case where second hint returns first
	h1Unlocker = make(chan struct{})
	h2Unlocker = make(chan struct{})
	go func() {
		h2Unlocker <- struct{}{}
		close(h2Unlocker)
		// let some time pass to ensure HintControllable2 returns first
		time.Sleep(100 * time.Millisecond)
		h1Unlocker <- struct{}{}
		close(h1Unlocker)
	}()
	_, err = ccs.Solve(wit, solver.WithNbTasks(2), solver.WithHints(HintControllable1, HintControllable2))
	assert.Equal(err.Error(), "hint controllable 2")

	// case where first hint returns first
	h1Unlocker = make(chan struct{})
	h2Unlocker = make(chan struct{})
	go func() {
		h1Unlocker <- struct{}{}
		close(h1Unlocker)
		// let some time pass to ensure HintControllable1 returns first
		time.Sleep(100 * time.Millisecond)
		h2Unlocker <- struct{}{}
		close(h2Unlocker)
	}()
	_, err = ccs.Solve(wit, solver.WithNbTasks(2), solver.WithHints(HintControllable1, HintControllable2))
	assert.Equal(err.Error(), "hint controllable 1")

	// with one task, the first hint always returns first. If not we get a deadlock (not tested here)
	_, err = ccs.Solve(wit, solver.WithNbTasks(1), solver.WithHints(HintControllable1, HintControllable2))
	assert.Equal(err.Error(), "hint controllable 1")
}
