package circuitdefer

import (
	"github.com/consensys/gnark/internal/kvstore"
)

type DeferKey struct{}

// type DeferFn func(frontend.API) error

func Put[T any](builder any, cb T) {
	// we use generics for type safety but to avoid import cycles.
	// TODO: compare with using any and type asserting at caller
	kv, ok := builder.(kvstore.Store)
	if !ok {
		panic("builder does not implement kvstore.Store")
	}
	val := kv.GetKeyValue(DeferKey{})
	var deferred []T
	if val == nil {
		deferred = []T{cb}
	} else {
		var ok bool
		deferred, ok = val.([]T)
		if !ok {
			panic("stored deferred functions not []func(frontend.API) error")
		}
	}
	deferred = append(deferred, cb)
	kv.SetKeyValue(DeferKey{}, deferred)
}

func GetAll[T any](builder any) []T {
	kv, ok := builder.(kvstore.Store)
	if !ok {
		panic("builder does not implement kvstore.Store")
	}
	val := kv.GetKeyValue(DeferKey{})
	if val == nil {
		return nil
	}
	deferred, ok := val.([]T)
	if !ok {
		panic("stored deferred functions not []func(frontend.API) error")
	}
	return deferred
}
