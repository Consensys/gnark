//go:build gofuzz
// +build gofuzz

package groth16

import (
	"encoding/hex"
	"io"
	"math/rand"
	"testing"
	"time"
)

// tests using fuzz.go (with go-fuzz) build tag
// ensure we run these in the CI workflow.

func TestCSFuzzed(t *testing.T) {
	const maxBytes = 7
	const testCount = 7
	var bytes [maxBytes]byte
	var i int
	seed := time.Now().UnixNano()
	defer func() {
		if r := recover(); r != nil {
			t.Error(r)
			t.Fatal("test panicked", i, hex.EncodeToString(bytes[:i]), "seed", seed)
		}
	}()
	r := rand.New(rand.NewSource(seed))

	for i = 1; i < maxBytes; i++ {
		for j := 0; j < testCount; j++ {
			if _, err := io.ReadFull(r, bytes[:i]); err != nil {
				t.Fatal("couldn't read random bytes", err)
			}

			if Fuzz(bytes[:i]) != 1 {
				t.Fatal("cs fuzz failed")
			}
		}
	}

}
