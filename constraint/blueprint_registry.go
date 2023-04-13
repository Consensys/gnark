package constraint

import (
	"hash/fnv"
	"reflect"
	"sync"

	"github.com/consensys/gnark/logger"
)

// TODO temporary refactor; maybe blueprints should be stored in the CS, + serialization bits.

type BlueprintID uint32

func init() {
	RegisterBlueprint(&BlueprintGenericSparseR1C{})
}

var (
	registry  = make(map[BlueprintID]Blueprint)
	registryM sync.RWMutex
)

// RegisterBlueprint registers a blueprint in the global registry.
func RegisterBlueprint(blueprints ...Blueprint) {
	registryM.Lock()
	defer registryM.Unlock()
	for _, b := range blueprints {
		key := GetBlueprintID(b)
		name := GetBlueprintName(b)
		if _, ok := registry[key]; ok {
			log := logger.Logger()
			log.Warn().Str("name", name).Msg("function registered multiple times")
			return
		}
		registry[key] = b
	}
}

// GetRegisteredBlueprints returns all registered blueprints.
func GetRegisteredBlueprints() []Blueprint {
	registryM.RLock()
	defer registryM.RUnlock()
	ret := make([]Blueprint, 0, len(registry))
	for _, v := range registry {
		ret = append(ret, v)
	}
	return ret
}

// GetBlueprintID is a reference function for computing the blueprint ID based on its name.
func GetBlueprintID(b Blueprint) BlueprintID {
	hf := fnv.New32a()
	name := GetBlueprintName(b)

	hf.Write([]byte(name)) // #nosec G104 -- does not err

	return BlueprintID(hf.Sum32())
}

func GetBlueprintName(b Blueprint) string {
	return reflect.TypeOf(b).String()
}
