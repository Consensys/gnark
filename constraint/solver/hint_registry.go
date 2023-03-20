package solver

import (
	"math/big"
	"sync"

	"github.com/consensys/gnark/logger"
)

func init() {
	RegisterHint(InvZeroHint)
}

var (
	registry  = make(map[HintID]Hint)
	registryM sync.RWMutex
)

// RegisterHint registers a hint function in the global registry.
func RegisterHint(hintFns ...Hint) {
	registryM.Lock()
	defer registryM.Unlock()
	for _, hintFn := range hintFns {
		key := GetHintID(hintFn)
		name := GetHintName(hintFn)
		if _, ok := registry[key]; ok {
			log := logger.Logger()
			log.Warn().Str("name", name).Msg("function registered multiple times")
			return
		}
		registry[key] = hintFn
	}
}

// GetRegisteredHints returns all registered hint functions.
func GetRegisteredHints() []Hint {
	registryM.RLock()
	defer registryM.RUnlock()
	ret := make([]Hint, 0, len(registry))
	for _, v := range registry {
		ret = append(ret, v)
	}
	return ret
}

// InvZeroHint computes the value 1/a for the single input a. If a == 0, returns 0.
func InvZeroHint(q *big.Int, inputs []*big.Int, results []*big.Int) error {
	result := results[0]

	// save input
	result.Set(inputs[0])

	// a == 0, return
	if result.IsUint64() && result.Uint64() == 0 {
		return nil
	}

	result.ModInverse(result, q)
	return nil
}
