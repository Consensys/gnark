package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type lookup2Circuit struct {
	V0, V1, V2, V3       frontend.Variable `gnark:",secret"`
	Selector0, Selector1 frontend.Variable `gnark:",secret"`
	Expected             frontend.Variable `gnark:",public"`
}

func (c *lookup2Circuit) Define(api frontend.API) error {
	selected := api.Lookup2(c.Selector0, c.Selector1, c.V0, c.V1, c.V2, c.V3)
	api.AssertIsEqual(selected, c.Expected)
	return nil
}

func init() {
	v0, v1, v2, v3 := 0, 1, 2, 3
	good := []frontend.Circuit{}
	bad := []frontend.Circuit{}
	for _, tc := range []struct {
		b0, b1     int
		expected   int
		unexpected int
	}{{0, 0, 0, 1}, {1, 0, 1, 0}, {0, 1, 2, 0}, {1, 1, 3, 0}} {
		good = append(good, &lookup2Circuit{v0, v1, v2, v3, tc.b0, tc.b1, tc.expected})
		bad = append(bad, &lookup2Circuit{v0, v1, v2, v3, tc.b0, tc.b1, tc.unexpected})
	}

	addNewEntry("lookup2", &lookup2Circuit{}, good, bad, nil)
}
