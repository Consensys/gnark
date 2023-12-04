package compress

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarshalRoundTrip(t *testing.T) {
	d := make([]int, 1000)
	for i := 0; i < 1000; i++ {
		var s Stream
		s.D = d[:rand.Intn(len(d))+1]  //#nosec G404 weak rng is fine here
		s.NbSymbs = rand.Intn(510) + 2 //#nosec G404 weak rng is fine here

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

func fillRandom(s Stream) {
	for i := range s.D {
		s.D[i] = rand.Intn(s.NbSymbs) //#nosec G404 weak rng is fine here
	}
}
