package dfa_search

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func test(t *testing.T, s, d []byte) []int {
	indexes := Search(s, d)
	foundAt := make([]bool, len(d))
	for _, i := range indexes {
		foundAt[i] = true
	}
	for i := range d {
		found := i+len(s) <= len(d) && bytesEqual(d[i:i+len(s)], s)
		assert.True(t, foundAt[i] == found, "i = %d, foundAt[i] = %v, found = %v", i, foundAt[i], found)
	}
	return indexes
}

func TestDfaAa(t *testing.T) {
	text := []byte{0, 0}
	dfa := createDfa(text)

	assert.Equal(t, []transition{{0, 1}}, dfa[0])
	assert.Equal(t, []transition{{0, 2}}, dfa[1])
	assert.Equal(t, []transition{{0, 2}}, dfa[2])
}

func TestDfaDo(t *testing.T) {
	text := []byte{1, 0}
	dfa := createDfa(text)

	assert.Equal(t, []transition{{1, 1}}, dfa[0])
	assert.Equal(t, []transition{{0, 2}, {1, 1}}, dfa[1])
	assert.Equal(t, []transition{{1, 1}}, dfa[2])
}

func TestAb(t *testing.T) {
	test(t, []byte{1, 0}, []byte{1, 0})
}

func TestLorem(t *testing.T) {
	text := "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
	indexes := test(t, []byte("do"), []byte(text))
	fmt.Println(indexes)
}

func TestSample(t *testing.T) {
	text, err := os.ReadFile("../test_cases/large/data.bin")
	assert.NoError(t, err)
	text = text[:320]
	indexes := Search(text[287:319], text)
	assert.Equal(t, []int{255, 287}, indexes)
}
