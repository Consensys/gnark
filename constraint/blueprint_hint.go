package constraint

import "github.com/consensys/gnark/constraint/solver"

type BlueprintGenericHint struct{}

func (b *BlueprintGenericHint) DecompressHint(h *HintMapping, calldata []uint32) {
	// ignore first call data == nbInputs
	h.HintID = solver.HintID(calldata[1])
	lenInputs := int(calldata[2])
	if cap(h.Inputs) >= lenInputs {
		h.Inputs = h.Inputs[:lenInputs]
	} else {
		h.Inputs = make([]LinearExpression, lenInputs)
	}

	j := 3
	for i := 0; i < lenInputs; i++ {
		n := int(calldata[j]) // len of linear expr
		j++
		if cap(h.Inputs[i]) >= n {
			h.Inputs[i] = h.Inputs[i][:0]
		} else {
			h.Inputs[i] = make(LinearExpression, 0, n)
		}
		for k := 0; k < n; k++ {
			h.Inputs[i] = append(h.Inputs[i], Term{CID: calldata[j], VID: calldata[j+1]})
			j += 2
		}
	}
	h.OutputRange.Start = calldata[j]
	h.OutputRange.End = calldata[j+1]
}

func (b *BlueprintGenericHint) CompressHint(h HintMapping) []uint32 {
	nbInputs := 1 // storing nb inputs
	nbInputs++    // hintID
	nbInputs++    // len(h.Inputs)
	for i := 0; i < len(h.Inputs); i++ {
		nbInputs++ // len of h.Inputs[i]
		nbInputs += len(h.Inputs[i]) * 2
	}

	nbInputs += 2 // output range start / end

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

	r = append(r, h.OutputRange.Start)
	r = append(r, h.OutputRange.End)
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
