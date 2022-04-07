package hint

import (
	"sync"

	"github.com/consensys/gnark/logger"
)

var registry = make(map[ID]Function)
var registryM sync.RWMutex

// Register registers an hint function in the global registry.
func Register(hintFn Function) {
	registryM.Lock()
	defer registryM.Unlock()
	key := UUID(hintFn)
	name := Name(hintFn)
	if _, ok := registry[key]; ok {
		log := logger.Logger()
		log.Warn().Str("name", name).Msg("function registered multiple times")
		return
	}
	registry[key] = hintFn
}

// GetRegistered returns all registered hint functions.
func GetRegistered() []Function {
	registryM.RLock()
	defer registryM.RUnlock()
	ret := make([]Function, 0, len(registry))
	for _, v := range registry {
		ret = append(ret, v)
	}
	return ret
}
