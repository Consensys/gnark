package gpoint

const scalarMul = `
// ScalarMul multiplies a by scalar
// algorithm: a special case of Pippenger described by Bootle:
// https://jbootle.github.io/Misc/pippenger.pdf
func (p *{{.Name}}Jac) ScalarMul(curve *Curve, a *{{.Name}}Jac, scalar fr.Element) *{{.Name}}Jac {
	// see MultiExp and pippenger documentation for more details about these constants / variables
	const s = 4
	const b = s
	const TSize = (1 << b) - 1
	var T [TSize]{{.Name}}Jac
	computeT := func(T []{{.Name}}Jac, t0 *{{.Name}}Jac) {
		T[0].Set(t0)
		for j := 1; j < (1<<b)-1; j = j + 2 {
			T[j].Set(&T[j/2]).Double()
			T[j+1].Set(&T[(j+1)/2]).Add(curve, &T[j/2])
		}
	}
	return p.pippenger(curve, []{{.Name}}Jac{*a}, []fr.Element{scalar}, s, b, T[:], computeT)
}
// ScalarMulByGen multiplies curve.{{toLower .Name}}Gen by scalar
// algorithm: a special case of Pippenger described by Bootle:
// https://jbootle.github.io/Misc/pippenger.pdf
func (p *{{.Name}}Jac) ScalarMulByGen(curve *Curve, scalar fr.Element) *{{.Name}}Jac {
	computeT := func(T []{{.Name}}Jac, t0 *{{.Name}}Jac) {}
	return p.pippenger(curve, []{{.Name}}Jac{curve.{{toLower .Name}}Gen}, []fr.Element{scalar}, sGen, bGen, curve.tGen{{.Name}}[:], computeT)
}
`

const multiExp = `
func (p *{{.Name}}Jac) MultiExpFormer(curve *Curve, points []{{ .Name}}Affine, scalars []fr.Element) chan {{.Name}}Jac  {
	debug.Assert(len(scalars) == len(points))
	chRes := make(chan {{.Name}}Jac, 1)
	// call windowed multi exp if input not large enough
	// we may want to force the API user to call the proper method in the first place
	const minPoints = 50 				// under 50 points, the windowed multi exp performs better
	if len(scalars) <= minPoints {
		_points := make([]{{ .Name}}Jac, len(points))
		for i := 0; i < len(points); i++ {
			points[i].ToJacobian(&_points[i])
		}
		go func() {
			p.WindowedMultiExp(curve, _points, scalars)
			chRes <- *p
		}()
		return chRes
		
	}
	// compute nbCalls and nbPointsPerBucket as a function of available CPUs
	const chunkSize = 64
	const totalSize = chunkSize * fr.ElementLimbs
	var nbBits, nbCalls uint64
	nbPoints := len(scalars)
	nbPointsPerBucket := 20		// empirical parameter to chose nbBits
	// set nbBbits and nbCalls
	nbBits = 0
	for len(scalars)/(1<<nbBits) >= nbPointsPerBucket {
		nbBits++
	}
	nbCalls = totalSize / nbBits
	if totalSize%nbBits > 0 {
		nbCalls++
	}
	const useAllCpus = false 
	// if we need to use all CPUs
	if useAllCpus {
		nbCpus := uint64(runtime.NumCPU())
		// goal here is to have at least as many calls as number of go routine we're allowed to spawn
		for nbCalls < nbCpus && nbPointsPerBucket < nbPoints {
			nbBits = 0
			for len(scalars)/(1<<nbBits) >= nbPointsPerBucket {
				nbBits++
			}
			nbCalls = totalSize / nbBits
			if totalSize%nbBits > 0 {
				nbCalls++
			}
			nbPointsPerBucket *= 2
		}
	}
	
	// result (1 per go routine)
	tmpRes := make([]chan {{ .Name}}Jac, nbCalls)
	chIndices := make([]chan struct{}, nbCalls)
	indices := make([][][]int, nbCalls)
	for i := 0; i < int(nbCalls); i++ {
		tmpRes[i] = make(chan {{.Name}}Jac, 1)
		chIndices[i] = make(chan struct{}, 1)
		indices[i] = make([][]int, 0, 1<<nbBits)
		for j := 0; j < len(indices[i]); j++ {
			indices[i][j] = make([]int, 0, nbPointsPerBucket)
		}
	}

	work := func(iStart, iEnd int) {
		chunks := make([]uint64, nbBits)
		offsets := make([]uint64, nbBits)
		for i := uint64(iStart); i < uint64(iEnd); i++ {
			start := i * nbBits
			debug.Assert(start != totalSize)
			var counter uint64
			for j := start;counter < nbBits  && (j < totalSize);j++ {
				chunks[counter] = j/chunkSize
				offsets[counter] = j%chunkSize
				counter++
			}
			c := 1 << counter
			indices[i] = make([][]int, c-1)
			var l uint64
			for j := 0; j < nbPoints; j++ {
				var index uint64
				for k := uint64(0); k < counter; k++ {
					l = scalars[j][chunks[k]] >> offsets[k]
					l &= 1
					l <<= k
					index += l
				}
				if index != 0 {
					indices[i][index-1] = append(indices[i][index-1], j)
				} 
			}
			chIndices[i] <- struct{}{}
			close(chIndices[i])
		}
	}
	pool.ExecuteAsyncReverse(0, int(nbCalls), work, false)

	// now we have the indices, let's compute what's inside

	debug.Assert(nbCalls > 1)
	pool.ExecuteAsyncReverse(0, int(nbCalls), func(start, end int){
		for i := start; i < end; i++ {
			var res  {{ .Name}}Jac
			sum := curve.{{toLower .Name}}Infinity
			<-chIndices[i]
			for j := len(indices[i]) - 1; j >= 0; j-- {
				for k := 0; k < len(indices[i][j]); k++ {
					sum.AddMixed(&points[indices[i][j][k]])
				}
				res.Add(curve, &sum)
			}
			tmpRes[i] <- res
			close(tmpRes[i])
		}
	}, false) 

	 go func() {
		p.Set(&curve.{{toLower .Name}}Infinity)
		debug.Assert(len(tmpRes)-2 >= 0)
		for i := len(tmpRes) - 1; i >= 0; i-- {
			for j := uint64(0); j < nbBits; j++ {
				p.Double()
			}
			r := <-tmpRes[i]
			p.Add(curve, &r)
		}
		chRes <- *p
	}()
	return chRes
}

// MultiExp complexity O(n)
func (p *{{.Name}}Jac) MultiExp(curve *Curve, points []{{.Name}}Affine, scalars []fr.Element) chan {{.Name}}Jac {
	nbPoints := len(points)
	debug.Assert(nbPoints == len(scalars))

	chRes := make(chan {{.Name}}Jac, 1)

	// under 50 points, the windowed multi exp performs better
	const minPoints = 50 
	if nbPoints <= minPoints {
		_points := make([]{{.Name}}Jac, len(points))
		for i := 0; i < len(points); i++ {
			points[i].ToJacobian(&_points[i])
		}
		go func() {
			p.WindowedMultiExp(curve, _points, scalars)
			chRes <- *p
		}()
		return chRes
	}

	// empirical values
	var nbChunks, chunkSize int
	var mask uint64
	if nbPoints <= 10000 {
		chunkSize = 8
	} else if nbPoints <= 80000 {
		chunkSize = 11
	} else if nbPoints <= 400000 {
		chunkSize = 13
	} else if nbPoints <= 800000 {
		chunkSize = 14
	} else {
		chunkSize = 16
	}

	const sizeScalar = fr.ElementLimbs * 64

	var bitsForTask [][]int
	if sizeScalar%chunkSize == 0 {
		counter := sizeScalar - 1
		nbChunks = sizeScalar / chunkSize
		bitsForTask = make([][]int, nbChunks)
		for i := 0; i < nbChunks; i++ {
			bitsForTask[i] = make([]int, chunkSize)
			for j := 0; j < chunkSize; j++ {
				bitsForTask[i][j] = counter
				counter--
			}
		}
	} else {
		counter := sizeScalar - 1
		nbChunks = sizeScalar/chunkSize + 1
		bitsForTask = make([][]int, nbChunks)
		for i := 0; i < nbChunks; i++ {
			if i < nbChunks-1 {
				bitsForTask[i] = make([]int, chunkSize)
			} else {
				bitsForTask[i] = make([]int, sizeScalar%chunkSize)
			}
			for j := 0; j < chunkSize && counter >= 0; j++ {
				bitsForTask[i][j] = counter
				counter--
			}
		}
	}

	accumulators := make([]{{.Name}}Jac, nbChunks)
	chIndices := make([]chan struct{}, nbChunks)
	chPoints := make([]chan struct{}, nbChunks)
	for i := 0; i < nbChunks; i++ {
		chIndices[i] = make(chan struct{}, 1)
		chPoints[i] = make(chan struct{}, 1)
	}

	mask = (1 << chunkSize) - 1
	nbPointsPerSlots := nbPoints / int(mask)
	// [][] is more efficient than [][][] for storage, elements are accessed via i*nbChunks+k
	indices := make([][]int, int(mask)*nbChunks) 
	for i := 0; i < int(mask)*nbChunks; i++ {
		indices[i] = make([]int, 0, nbPointsPerSlots)
	}

	// if chunkSize=8, nbChunks=32 (the scalars are chunkSize*nbChunks bits long)
	// for each 32 chunk, there is a list of 2**8=256 list of indices
	// for the i-th chunk, accumulateIndices stores in the k-th list all the indices of points
	// for which the i-th chunk of 8 bits is equal to k 
	accumulateIndices := func(cpuID, nbTasks, n int) {
		for i := 0; i < nbTasks; i++ {
			task := cpuID + i*n
			idx := task*int(mask)-1
			for j := 0; j < nbPoints; j++ {
				val := 0
				for k := 0; k < len(bitsForTask[task]); k++ {
					val = val << 1
					c := bitsForTask[task][k] / int(64)
					o := bitsForTask[task][k] % int(64)
					b := (scalars[j][c] >> o) & 1
					val += int(b)
				}
				if val != 0 {
					indices[idx+int(val)] = append(indices[idx+int(val)], j)
				}
			}
			chIndices[task] <- struct{}{}
			close(chIndices[task])
		}
	}

	// if chunkSize=8, nbChunks=32 (the scalars are chunkSize*nbChunks bits long)
	// for each chunk, sum up elements in index 0, add to current result, sum up elements
	// in index 1, add to current result, etc, up to 255=2**8-1
	accumulatePoints := func(cpuID, nbTasks, n int) {
		for i := 0; i < nbTasks; i++ {
			var tmp {{toLower .Name}}JacExtended
			var _tmp {{.Name}}Jac
			task := cpuID + i*n

			// init points
			tmp.SetInfinity()
			accumulators[task].Set(&curve.{{toLower .Name}}Infinity)

			// wait for indices to be ready
			<-chIndices[task]

			for j := int(mask - 1); j >= 0; j-- {
				for _, k := range indices[task*int(mask)+j] {
					tmp.mAdd(&points[k])
				}
				tmp.ToJac(&_tmp)
				accumulators[task].Add(curve, &_tmp)
			}
			chPoints[task] <- struct{}{}
			close(chPoints[task])
		}
	}

	// double and add algo to collect all small reductions
	reduce := func() {
		var res {{.Name}}Jac
		res.Set(&curve.{{toLower .Name}}Infinity)
		for i := 0; i < nbChunks; i++ {
			for j := 0; j < len(bitsForTask[i]); j++ {
				res.Double()
			}
			<-chPoints[i]
			res.Add(curve, &accumulators[i])
		}
		p.Set(&res)
		chRes <- *p
	}

	nbCpus := runtime.NumCPU()
	nbTasksPerCpus := nbChunks / nbCpus
	remainingTasks := nbChunks % nbCpus
	for i := 0; i < nbCpus; i++ {
		if remainingTasks > 0 {
			go accumulateIndices(i, nbTasksPerCpus+1, nbCpus)
			go accumulatePoints(i, nbTasksPerCpus+1, nbCpus)
			remainingTasks--
		} else {
			go accumulateIndices(i, nbTasksPerCpus, nbCpus)
			go accumulatePoints(i, nbTasksPerCpus, nbCpus)
		}
	}

	go reduce()

	return chRes
}

`

const windowedMultiExp = `
// WindowedMultiExp set p = scalars[0]*points[0] + ... + scalars[n]*points[n]
// assume: scalars in non-Montgomery form!
// assume: len(points)==len(scalars)>0, len(scalars[i]) equal for all i
// algorithm: a special case of Pippenger described by Bootle:
// https://jbootle.github.io/Misc/pippenger.pdf
// uses all availables runtime.NumCPU()
func (p *{{.Name}}Jac) WindowedMultiExp(curve *Curve, points []{{.Name}}Jac, scalars []fr.Element) *{{.Name}}Jac {
	var lock sync.Mutex
	pool.Execute(0, len(points), func(start, end int) {
		var t {{.Name}}Jac
		t.multiExp(curve, points[start:end], scalars[start:end])
		lock.Lock()
		p.Add(curve, &t)
		lock.Unlock()
	}, false)
	return p
}
// multiExp set p = scalars[0]*points[0] + ... + scalars[n]*points[n]
// assume: scalars in non-Montgomery form!
// assume: len(points)==len(scalars)>0, len(scalars[i]) equal for all i
// algorithm: a special case of Pippenger described by Bootle:
// https://jbootle.github.io/Misc/pippenger.pdf
func (p *{{.Name}}Jac) multiExp(curve *Curve, points []{{.Name}}Jac, scalars []fr.Element) *{{.Name}}Jac {
	const s = 4 // s from Bootle, we choose s divisible by scalar bit length
	const b = s // b from Bootle, we choose b equal to s
	// WARNING! This code breaks if you switch to b!=s
	// Because we chose b=s, each set S_i from Bootle is simply the set of points[i]^{2^j} for each j in [0:s]
	// This choice allows for simpler code
	// If you want to use b!=s then the S_i from Bootle are different
	const TSize = (1 << b) - 1 // TSize is size of T_i sets from Bootle, equal to 2^b - 1
	// Store only one set T_i at a time---don't store them all!
	var T [TSize]{{.Name}}Jac // a set T_i from Bootle, the set of g^j for j in [1:2^b] for some choice of g
	computeT := func(T []{{.Name}}Jac, t0 *{{.Name}}Jac) {
		T[0].Set(t0)
		for j := 1; j < (1<<b)-1; j = j + 2 {
			T[j].Set(&T[j/2]).Double()
			T[j+1].Set(&T[(j+1)/2]).Add(curve, &T[j/2])
		}
	}
	return p.pippenger(curve, points, scalars, s, b, T[:], computeT)
}
// algorithm: a special case of Pippenger described by Bootle:
// https://jbootle.github.io/Misc/pippenger.pdf
func (p *{{.Name}}Jac) pippenger(curve *Curve, points []{{.Name}}Jac, scalars []fr.Element, s, b uint64, T []{{.Name}}Jac, computeT func(T []{{.Name}}Jac, t0 *{{.Name}}Jac)) *{{.Name}}Jac {
	var t, selectorIndex, ks int
	var selectorMask, selectorShift, selector uint64
	
	t = fr.ElementLimbs * 64 / int(s) // t from Bootle, equal to (scalar bit length) / s
	selectorMask = (1 << b) - 1 // low b bits are 1
	morePoints := make([]{{.Name}}Jac, t)       // morePoints is the set of G'_k points from Bootle
	for k := 0; k < t; k++ {
		morePoints[k].Set(&curve.{{toLower .Name}}Infinity)
	}
	for i := 0; i < len(points); i++ {
		// compute the set T_i from Bootle: all possible combinations of elements from S_i from Bootle
		computeT(T, &points[i])
		// for each morePoints: find the right T element and add it
		for k := 0; k < t; k++ {
			ks = k * int(s)
			selectorIndex = ks / 64
			selectorShift = uint64(ks - (selectorIndex * 64))
			selector = (scalars[i][selectorIndex] & (selectorMask << selectorShift)) >> selectorShift
			if selector != 0 {
				morePoints[k].Add(curve, &T[selector-1])
			}
		}
	}
	// combine morePoints to get the final result
	p.Set(&morePoints[t-1])
	for k := t - 2; k >= 0; k-- {
		for j := uint64(0); j < s; j++ {
			p.Double()
		}
		p.Add(curve, &morePoints[k])
	}
	return p
}
`
