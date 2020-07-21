package frontend

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConstraintTag(t *testing.T) {
	assert := require.New(t)

	cs := NewConstraintSystem()

	tagLen := func(cs *CS, v Variable) int {
		return len(cs.wireTags[v.id(cs)])
	}

	a := cs.ALLOCATE(12)
	assert.True(tagLen(&cs, a) == 0, "untagged constraint shouldn't have tags")
	cs.Tag(a, "a")
	assert.True(tagLen(&cs, a) == 1, "a should have 1 tag")
	cs.Tag(a, "b")
	assert.True(tagLen(&cs, a) == 2, "a should have 2 tag")

	x := cs.PUBLIC_INPUT("x")
	assert.True(tagLen(&cs, x) == 0, "a secret/public is not tagged by default")

}

func TestDuplicateTag(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("declaring same tag name, code should panic")
		}
	}()

	assert := require.New(t)

	cs := NewConstraintSystem()

	tagLen := func(cs *CS, v Variable) int {
		return len(cs.wireTags[v.id(cs)])
	}

	a := cs.ALLOCATE(12)
	assert.True(tagLen(&cs, a) == 0, "untagged constraint shouldn't have tags")
	cs.Tag(a, "a")
	assert.True(tagLen(&cs, a) == 1, "a should have 1 tag")
	cs.Tag(a, "b")
	assert.True(tagLen(&cs, a) == 2, "a should have 2 tag")
	cs.Tag(a, "b") // duplicate

}
