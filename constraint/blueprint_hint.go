package constraint

import "github.com/consensys/gnark/constraint/solver"

type BlueprintGenericHint struct {
}

func (b *BlueprintGenericHint) DecompressHint(h *HintMapping, calldata []uint32) {
	// ignore first call data == nbInputs
	h.HintID = solver.HintID(calldata[1])
	lenInputs := int(calldata[2])
	h.Inputs = make([]LinearExpression, lenInputs)
	h.Outputs = h.Outputs[:0]
	j := 3
	for i := 0; i < lenInputs; i++ {
		n := int(calldata[j]) // len of linear expr
		j++
		for k := 0; k < n; k++ {
			h.Inputs[i] = append(h.Inputs[i], Term{CID: calldata[j], VID: calldata[j+1]})
			j += 2
		}
	}
	for j < len(calldata) {
		h.Outputs = append(h.Outputs, int(calldata[j]))
		j++
	}
}

func (b *BlueprintGenericHint) CompressHint(h HintMapping) []uint32 {
	nbInputs := 1 // storing nb inputs
	nbInputs++    // hintID
	nbInputs++    // len(h.Inputs)
	for i := 0; i < len(h.Inputs); i++ {
		nbInputs++ // len of h.Inputs[i]
		nbInputs += len(h.Inputs[i]) * 2
	}

	nbInputs += len(h.Outputs)

	r := make([]uint32, 0, nbInputs)
	r = append(r, uint32(nbInputs))
	r = append(r, uint32(h.HintID))
	r = append(r, uint32(len(h.Inputs)))

	for _, l := range h.Inputs {
		r = append(r, uint32(len(l)))
		for _, t := range l {
			r = append(r, uint32(t.CoeffID()), uint32(t.WireID()))
		}
	}

	for _, t := range h.Outputs {
		r = append(r, uint32(t))
	}
	if len(r) != nbInputs {
		panic("invalid")
	}
	return r
}

func (b *BlueprintGenericHint) NbInputs() int {
	return -1
}
func (b *BlueprintGenericHint) NbConstraints() int {
	return 0
}
