// Package kvstore implements simple key-value store
//
// It is without synchronization and allows any comparable keys. The main use of
// this package is for sharing singletons when building a circuit.
package kvstore

type Store interface {
	SetKeyValue(key, value any)
	GetKeyValue(key any) (value any)
}

type impl struct {
	db map[any]any
}

func New() Store {
	return &impl{
		db: make(map[any]any),
	}
}

func (c *impl) SetKeyValue(key, value any) {
	c.db[key] = value
}

func (c *impl) GetKeyValue(key any) any {
	return c.db[key]
}
