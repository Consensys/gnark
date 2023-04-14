package constraint

import "unsafe"

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
	nbInputs := 3 + 2*(len(c.L)+len(c.R)+len(c.O))
	r := make([]uint32, 0, nbInputs)
	r = append(r, uint32(nbInputs))
	r = append(r, uint32(len(c.L)), uint32(len(c.R)))
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

func (b *BlueprintGenericR1C) DecompressR1C(c *R1C, calldata []uint32) {
	lenL := int(calldata[1])
	lenR := int(calldata[2])
	lenO := int(((calldata[0] - 3) / 2) - uint32(lenL) - uint32(lenR))

	j := 3
	// TODO @gbotrel we may not want to use unsafe ptr here since with meta/block of blueprints
	// we will end up modifying the resulting constraint.
	c.L = unsafe.Slice((*Term)(unsafe.Pointer(unsafe.SliceData(calldata[j:j+2*lenL]))), lenL)
	j += 2 * lenL
	c.R = unsafe.Slice((*Term)(unsafe.Pointer(unsafe.SliceData(calldata[j:j+2*lenR]))), lenR)
	j += 2 * lenR
	c.O = unsafe.Slice((*Term)(unsafe.Pointer(unsafe.SliceData(calldata[j:j+2*lenO]))), lenO)
}
