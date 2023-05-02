package constraint

// BlueprintGenericR1C implements Blueprint and BlueprintR1C.
// Encodes
//
//	L * R == 0
type BlueprintGenericR1C struct{}

func (b *BlueprintGenericR1C) CalldataSize() int {
	// size of linear expressions are unknown.
	return -1
}
func (b *BlueprintGenericR1C) NbConstraints() int {
	return 1
}
func (b *BlueprintGenericR1C) NbOutputs() int {
	return 0
}

func (b *BlueprintGenericR1C) CompressR1C(c *R1C) []uint32 {
	// we store total nb inputs, len L, len R, len O, and then the "flatten" linear expressions
	nbInputs := 4 + 2*(len(c.L)+len(c.R)+len(c.O))
	r := getBuffer(nbInputs)
	r = append(r, uint32(nbInputs))
	r = append(r, uint32(len(c.L)), uint32(len(c.R)), uint32(len(c.O)))
	for _, t := range c.L {
		r = append(r, uint32(t.CoeffID()), uint32(t.WireID()))
	}
	for _, t := range c.R {
		r = append(r, uint32(t.CoeffID()), uint32(t.WireID()))
	}
	for _, t := range c.O {
		r = append(r, uint32(t.CoeffID()), uint32(t.WireID()))
	}
	return r
}

func (b *BlueprintGenericR1C) DecompressR1C(c *R1C, inst Instruction) {
	copySlice := func(slice *LinearExpression, expectedLen, idx int) {
		if cap(*slice) >= expectedLen {
			(*slice) = (*slice)[:expectedLen]
		} else {
			(*slice) = make(LinearExpression, expectedLen, expectedLen*2)
		}
		for k := 0; k < expectedLen; k++ {
			(*slice)[k].CID = inst.Calldata[idx]
			idx++
			(*slice)[k].VID = inst.Calldata[idx]
			idx++
		}
	}

	lenL := int(inst.Calldata[1])
	lenR := int(inst.Calldata[2])
	lenO := int(inst.Calldata[3])

	const offset = 4
	copySlice(&c.L, lenL, offset)
	copySlice(&c.R, lenR, offset+2*lenL)
	copySlice(&c.O, lenO, offset+2*(lenL+lenR))
}

func (b *BlueprintGenericR1C) Wires(inst Instruction) func(cb func(wire uint32)) {
	return func(cb func(wire uint32)) {
		lenL := int(inst.Calldata[1])
		lenR := int(inst.Calldata[2])
		lenO := int(inst.Calldata[3])

		appendWires := func(expectedLen, idx int) {
			for k := 0; k < expectedLen; k++ {
				idx++
				cb(inst.Calldata[idx])
				idx++
			}
		}

		const offset = 4
		appendWires(lenL, offset)
		appendWires(lenR, offset+2*lenL)
		appendWires(lenO, offset+2*(lenL+lenR))
	}
}

// since frontend is single threaded, to avoid allocating slices at each compress call
// we transit the compressed output through here
var bufCalldata []uint32

// getBuffer return a slice with at least the given capacity to use in Compress methods
// this is obviously not thread safe, but the frontend is single threaded anyway.
func getBuffer(size int) []uint32 {
	if cap(bufCalldata) < size {
		bufCalldata = make([]uint32, 0, size*2)
	}
	bufCalldata = bufCalldata[:0]
	return bufCalldata
}
