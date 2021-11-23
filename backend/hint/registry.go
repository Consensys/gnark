package hint

import (
	"fmt"
	"sync"
)

var registry = make(map[ID]Function)
var registryM sync.RWMutex

// Register registers a hint function in the global registry. All registered
// hint functions can be retrieved with a call to GetAll(). It is an error to
// register a single function twice and results in a panic.
func Register(hintFn Function) {
	registryM.Lock()
	defer registryM.Unlock()
	key := UUID(hintFn)
	if _, ok := registry[key]; ok {
		panic(fmt.Sprintf("function %d registered twice", key))
	}
	registry[key] = hintFn
}

// GetAll returns all registered hint functions.
func GetAll() []Function {
	registryM.RLock()
	defer registryM.RUnlock()
	ret := make([]Function, 0, len(registry))
	for _, v := range registry {
		ret = append(ret, v)
	}
	return ret
}
