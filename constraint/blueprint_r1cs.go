package constraint

// BlueprintGenericR1C implements Blueprint and BlueprintR1C.
// Encodes
//
//	L * R == 0
type BlueprintGenericR1C struct{}

func (b *BlueprintGenericR1C) NbInputs() int {
	// size of linear expressions are unknown.
	return -1
}
func (b *BlueprintGenericR1C) NbConstraints() int {
	return 1
}

func (b *BlueprintGenericR1C) CompressR1C(c *R1C) []uint32 {
	// we store total nb inputs, len L, len R, len O, and then the "flatten" linear expressions
	nbInputs := 4 + 2*(len(c.L)+len(c.R)+len(c.O))
	if cap(bufR1C) < nbInputs {
		bufR1C = make([]uint32, 0, nbInputs*2)
	}
	bufR1C = bufR1C[:0]
	bufR1C = append(bufR1C, uint32(nbInputs))
	bufR1C = append(bufR1C, uint32(len(c.L)), uint32(len(c.R)), uint32(len(c.O)))
	for _, t := range c.L {
		bufR1C = append(bufR1C, uint32(t.CoeffID()), uint32(t.WireID()))
	}
	for _, t := range c.R {
		bufR1C = append(bufR1C, uint32(t.CoeffID()), uint32(t.WireID()))
	}
	for _, t := range c.O {
		bufR1C = append(bufR1C, uint32(t.CoeffID()), uint32(t.WireID()))
	}
	return bufR1C
}

func (b *BlueprintGenericR1C) DecompressR1C(c *R1C, calldata []uint32) {
	copySlice := func(slice *LinearExpression, expectedLen, idx int) {
		if cap(*slice) >= expectedLen {
			(*slice) = (*slice)[:expectedLen]
		} else {
			(*slice) = make(LinearExpression, expectedLen, expectedLen*2)
		}
		for k := 0; k < expectedLen; k++ {
			(*slice)[k].CID = calldata[idx]
			idx++
			(*slice)[k].VID = calldata[idx]
			idx++
		}
	}

	lenL := int(calldata[1])
	lenR := int(calldata[2])
	lenO := int(calldata[3])

	const offset = 4
	copySlice(&c.L, lenL, offset)
	copySlice(&c.R, lenR, offset+2*lenL)
	copySlice(&c.O, lenO, offset+2*(lenL+lenR))
}

// since frontend is single threaded, to avoid allocating slices at each compress call
// we transit the compressed output through here
var bufR1C []uint32
