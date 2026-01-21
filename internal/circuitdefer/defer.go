package circuitdefer

import (
	"github.com/consensys/gnark/internal/kvstore"
)

type deferKey struct{}

// Put stores a deferred function cb into the key-value store for later
// retrieval. The new function is appended to the list of deferred functions,
// and later retrieved in same order as added (FIFO order).
func Put[T any](builder any, cb T) {
	// we use generics for type safety but to avoid import cycles.
	// TODO: compare with using any and type asserting at caller
	kv, ok := builder.(kvstore.Store)
	if !ok {
		panic("builder does not implement kvstore.Store")
	}
	val := kv.GetKeyValue(deferKey{})
	var deferred []T
	if val != nil {
		var ok bool
		deferred, ok = val.([]T)
		if !ok {
			panic("stored deferred functions not []func(frontend.API) error")
		}
	}
	deferred = append(deferred, cb)
	kv.SetKeyValue(deferKey{}, deferred)
}

// GetAll retrieves all deferred functions of type T from the key-value store.
//
// Deferred functions are returned in the same order as they were added (FIFO
// order).
//
// Deferred functions are not removed from the store.
//
// Deferred functions can defer other functions. So when iterating over all deferred
// functions, it is better to use a loop calling [GetAll] at each iteration to
// catch newly added deferred functions.
func GetAll[T any](builder any) []T {
	kv, ok := builder.(kvstore.Store)
	if !ok {
		panic("builder does not implement kvstore.Store")
	}
	val := kv.GetKeyValue(deferKey{})
	if val == nil {
		return nil
	}
	deferred, ok := val.([]T)
	if !ok {
		panic("stored deferred functions not []func(frontend.API) error")
	}
	return deferred
}
