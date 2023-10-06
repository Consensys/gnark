package compress

// TODO: We no longer care about gas; remove these

func ByteGasCost(b byte) uint64 {
	if b == 0 {
		return 1
	}
	return 4
}

func BytesGasCost(d []byte) uint64 {
	cost := uint64(0)
	for _, b := range d {
		if b == 0 {
			cost++
		} else {
			cost += 4
		}
	}
	return cost
}
