package gkr

import (
	"fmt"
	"hash"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	snarkHash "github.com/consensys/gnark/std/hash"
)

var (
	hashRegistryLock sync.Mutex
	snarkHashes      map[string]func() snarkHash.FieldHasher
	curveHashes      = make(map[string]map[ecc.ID]func() hash.Hash)
)

func RegisterSnarkHashBuilder(name string, builder func() snarkHash.FieldHasher) {
	hashRegistryLock.Lock()
	defer hashRegistryLock.Unlock()

	if _, ok := snarkHashes[name]; ok {
		panic(fmt.Errorf("hash function \"%s\" already registered", name))
	}
	snarkHashes[name] = builder
}

func NewSnarkHash(name string) (snarkHash.FieldHasher, error) {
	hashRegistryLock.Lock()
	defer hashRegistryLock.Unlock()

	if _, ok := snarkHashes[name]; !ok {
		return nil, fmt.Errorf("hash function \"%s\" not found", name)
	}
	return snarkHashes[name](), nil
}

func RegisterHashBuilder(name string, curve ecc.ID, builder func() hash.Hash) {
	hashRegistryLock.Lock()
	defer hashRegistryLock.Unlock()

	if _, ok := curveHashes[name]; !ok {
		curveHashes[name] = make(map[ecc.ID]func() hash.Hash)
	}
	if _, ok := curveHashes[name][curve]; ok {
		panic(fmt.Errorf("hash function \"%s\" already registered for curve \"%s\"", name, curve))
	}
	curveHashes[name][curve] = builder
}

func NewHash(name string, curve ecc.ID) (hash.Hash, error) {
	hashRegistryLock.Lock()
	defer hashRegistryLock.Unlock()

	if _, ok := curveHashes[name]; !ok {
		return nil, fmt.Errorf("hash function \"%s\" not found", name)
	}
	if _, ok := curveHashes[name][curve]; !ok {
		return nil, fmt.Errorf("hash function \"%s\" not found for curve \"%s\"", name, curve)
	}
	return curveHashes[name][curve](), nil
}
