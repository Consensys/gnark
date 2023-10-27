package compress

import (
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

// TODO Gopter tests?

func fillRandom(s Stream) {
	for i := range s.D {
		s.D[i] = rand.Intn(s.NbSymbs)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	d := make([]int, 1000)
	for i := 0; i < 1000; i++ {
		s := Stream{
			D:       d[:rand.Intn(len(d))+1],
			NbSymbs: rand.Intn(510) + 2,
		}
		testMarshal(t, s)
	}
}

func testMarshal(t *testing.T, s Stream) {
	fillRandom(s)
	marshalled := s.Marshal()
	sBack := Stream{NbSymbs: s.NbSymbs}
	sBack.Unmarshal(marshalled)
	assert.Equal(t, s, sBack, "marshalling round trip failed for nbSymbs %d and size %d", s.NbSymbs, len(s.D))
}
