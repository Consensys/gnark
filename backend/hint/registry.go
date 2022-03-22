package hint

import (
	"fmt"
	"strings"
	"sync"
)

var registry = make(map[ID]Function)
var registryM sync.RWMutex

// Register registers an annotated hint function in the global registry. It is an
// error to register a single function twice and results in a panic.
func Register(hintFn Function) {
	registryM.Lock()
	defer registryM.Unlock()
	key := UUID(hintFn)
	name := Name(hintFn)
	const lambda = ".glob.."
	const definedOnInterface = "-"
	if _, ok := registry[key]; ok {
		// for gnark std hints, there is a special path
		if strings.HasPrefix(name, "github.com/consensys/gnark/") {
			return
		}
		panic(fmt.Sprintf("function %s registered twice", name))
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
