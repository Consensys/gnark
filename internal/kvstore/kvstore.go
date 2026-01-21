// Package kvstore implements simple key-value store
//
// It is without synchronization and allows any comparable keys. The main use of
// this package is for sharing singletons when building a circuit.
package kvstore

// Store is a simple key-value store used at circuit compilation time.
// It is without synchronization and allows any comparable keys. The main use of
// this package is for sharing singletons when building a circuit.
//
// To avoid key collisions, it is recommended to use empty struct types as keys.
// This approach also allows to have parametric keys where the struct has
// internal fields defining the parameters.
//
// Example:
//
//	type ctxMySingletonKey struct{}
//
//	func getMySingleton(api frontend.API) *MySingleton {
//	    kv, ok := api.Compiler().(kvstore.Store)
//	    if !ok {
//	        panic("builder should implement key-value store")
//	    }
//	    s := kv.GetKeyValue(ctxMySingletonKey{})
//	    if s != nil {
//	        if st, ok := s.(*MySingleton); ok {
//	            return st
//	        } else {
//	            panic("stored singleton is of invalid type")
//	        }
//	    }
//	    st := &MySingleton{}
//	    kv.SetKeyValue(ctxMySingletonKey{}, st)
//	    return st
//	}
type Store interface {
	// SetKeyValue sets the value for the given key. Key has to be comparable.
	SetKeyValue(key, value any)

	// GetKeyValue gets the value for the given key. Returns nil if not found.
	// Key has to be comparable.
	//
	// The user is responsible for type asserting the returned value.
	GetKeyValue(key any) (value any)
}

type impl struct {
	db map[any]any
}

// New returns a new in-memory key-value store.
func New() Store {
	return &impl{
		db: make(map[any]any),
	}
}

func (c *impl) SetKeyValue(key, value any) {
	// we use unsynchronized access as this is only used at circuit compilation
	// time and compilation happens in a single thread. If that changes, we need
	// to add synchronization here.
	c.db[key] = value
}

func (c *impl) GetKeyValue(key any) any {
	// we use unsynchronized access as this is only used at circuit compilation
	// time and compilation happens in a single thread. If that changes, we need
	// to add synchronization here.
	return c.db[key]
}
