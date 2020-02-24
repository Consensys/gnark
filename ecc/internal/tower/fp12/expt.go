package fp12

const expt = `
const tAbsVal uint64 = {{.T}} {{ if .TNeg }}// negative{{- end }}

// Expt set z to x^t in {{.Name}} and return z
// TODO make a ExptAssign method that assigns the result to self; then this method can assert fail if z != x
// TODO Expt is the only method that depends on tAbsVal.  The rest of the tower does not depend on this value.  Logically, Expt should be separated from the rest of the tower.
func (z *{{.Name}}) Expt(x *{{.Name}}) *{{.Name}} {
	// TODO what if x==0?
	// TODO make this match Element.Exp: x is a non-pointer?
	{{- if (eq .T "9586122913090633729" ) }}

		// tAbsVal in binary: 1000010100001000110000000000000000000000000000000000000000000001
		// drop the low 46 bits (all 0 except the least significant bit): 100001010000100011 = 136227
		// Shortest addition chains can be found at https://wwwhomes.uni-bielefeld.de/achim/addition_chain.html

		var result, x33 {{.Name}}

		// a shortest addition chain for 136227
		result.Set(x)             // 0                1
		result.Square(&result)    // 1( 0)            2
		result.Square(&result)    // 2( 1)            4
		result.Square(&result)    // 3( 2)            8
		result.Square(&result)    // 4( 3)           16
		result.Square(&result)    // 5( 4)           32
		result.Mul(&result, x)    // 6( 5, 0)        33
		x33.Set(&result)          // save x33 for step 14
		result.Square(&result)    // 7( 6)           66
		result.Square(&result)    // 8( 7)          132
		result.Square(&result)    // 9( 8)          264
		result.Square(&result)    // 10( 9)          528
		result.Square(&result)    // 11(10)         1056
		result.Square(&result)    // 12(11)         2112
		result.Square(&result)    // 13(12)         4224
		result.Mul(&result, &x33) // 14(13, 6)      4257
		result.Square(&result)    // 15(14)         8514
		result.Square(&result)    // 16(15)        17028
		result.Square(&result)    // 17(16)        34056
		result.Square(&result)    // 18(17)        68112
		result.Mul(&result, x)    // 19(18, 0)     68113
		result.Square(&result)    // 20(19)       136226
		result.Mul(&result, x)    // 21(20, 0)    136227
	
		// the remaining 46 bits
		for i := 0; i < 46; i++ {
			result.Square(&result)
		}
		result.Mul(&result, x)
	
	{{- else }}
		var result {{.Name}}
		result.Set(x)

		l := bits.Len64(tAbsVal) - 2
		for i := l; i >= 0; i-- {
			result.Square(&result)
			if tAbsVal&(1<<uint(i)) != 0 {
				result.Mul(&result, x)
			}
		}
	{{- end }}

	{{- if .TNeg }}
		result.Conjugate(&result) // because tAbsVal is negative
	{{- end }}

	z.Set(&result)
	return z
}

// FinalExponentiation computes the final expo x**((p**12 - 1)/r)
func (z *{{.Name}}) FinalExponentiation(x *{{.Name}}) *{{.Name}} {

{{- /* TODO add a curve family parameter for BLS12, BN and use it here */}}
{{- if (eq .Fp6NonResidue "9,1") and (eq .Fp "21888242871839275222246405745257275088696311157297823662689037894645226208583") }}
	// For BN curves use Section 5 of https://eprint.iacr.org/2008/490.pdf; their x is our t

	// TODO modify sage test points script to include a factor of 3 in the final exponent for BLS curves but not BN curves
	var mt [4]e12 // mt[i] is m^(t^i)

	// set m[0] = x^((p^6-1)*(p^2+1))
	{
		mt[0].Set(x)
		var temp e12
		temp.FrobeniusCube(&mt[0]).
			FrobeniusCube(&temp)

		mt[0].Inverse(&mt[0])
		temp.Mul(&temp, &mt[0])

		mt[0].FrobeniusSquare(&temp).
			Mul(&mt[0], &temp)
	}

	// "hard part": set z = m[0]^((p^4-p^2+1)/r)

	mt[1].Expt(&mt[0])
	mt[2].Expt(&mt[1])
	mt[3].Expt(&mt[2])

	// prepare y
	var y [7]e12

	y[1].InverseUnitary(&mt[0])
	y[4].Set(&mt[1])
	y[5].InverseUnitary(&mt[2])
	y[6].Set(&mt[3])

	mt[0].Frobenius(&mt[0])
	mt[1].Frobenius(&mt[1])
	mt[2].Frobenius(&mt[2])
	mt[3].Frobenius(&mt[3])

	y[0].Set(&mt[0])
	y[3].InverseUnitary(&mt[1])
	y[4].Mul(&y[4], &mt[2]).InverseUnitary(&y[4])
	y[6].Mul(&y[6], &mt[3]).InverseUnitary(&y[6])

	mt[0].Frobenius(&mt[0])
	mt[2].Frobenius(&mt[2])

	y[0].Mul(&y[0], &mt[0])
	y[2].Set(&mt[2])

	mt[0].Frobenius(&mt[0])

	y[0].Mul(&y[0], &mt[0])

	// compute addition chain
	var t [2]e12

	t[0].Square(&y[6])
	t[0].Mul(&t[0], &y[4])
	t[0].Mul(&t[0], &y[5])
	t[1].Mul(&y[3], &y[5])
	t[1].Mul(&t[1], &t[0])
	t[0].Mul(&t[0], &y[2])
	t[1].Square(&t[1])
	t[1].Mul(&t[1], &t[0])
	t[1].Square(&t[1])
	t[0].Mul(&t[1], &y[1])
	t[1].Mul(&t[1], &y[0])
	t[0].Square(&t[0])
	z.Mul(&t[0], &t[1])

	return z

{{- else }}
	// For BLS curves use Section 3 of https://eprint.iacr.org/2016/130.pdf; "hard part" is Algorithm 1 of https://eprint.iacr.org/2016/130.pdf
	var result {{.Name}}
	result.Set(x)

	// memalloc
	var t [6]{{.Name}}

	// buf = x**(p^6-1)
	t[0].FrobeniusCube(&result).
		FrobeniusCube(&t[0])

	result.Inverse(&result)
	t[0].Mul(&t[0], &result)

	// x = (x**(p^6-1)) ^(p^2+1)
	result.FrobeniusSquare(&t[0]).
		Mul(&result, &t[0])

	// hard part (up to permutation)
	// performs the hard part of the final expo
	// Algorithm 1 of https://eprint.iacr.org/2016/130.pdf
	// The result is the same as p**4-p**2+1/r, but up to permutation (it's 3* (p**4 -p**2 +1 /r)), ok since r=1 mod 3)

	t[0].InverseUnitary(&result).Square(&t[0])
	t[5].Expt(&result)
	t[1].Square(&t[5])
	t[3].Mul(&t[0], &t[5])

	t[0].Expt(&t[3])
	t[2].Expt(&t[0])
	t[4].Expt(&t[2])

	t[4].Mul(&t[1], &t[4])
	t[1].Expt(&t[4])
	t[3].InverseUnitary(&t[3])
	t[1].Mul(&t[3], &t[1])
	t[1].Mul(&t[1], &result)

	t[0].Mul(&t[0], &result)
	t[0].FrobeniusCube(&t[0])

	t[3].InverseUnitary(&result)
	t[4].Mul(&t[3], &t[4])
	t[4].Frobenius(&t[4])

	t[5].Mul(&t[2], &t[5])
	t[5].FrobeniusSquare(&t[5])

	t[5].Mul(&t[5], &t[0])
	t[5].Mul(&t[5], &t[4])
	t[5].Mul(&t[5], &t[1])

	result.Set(&t[5])

	z.Set(&result)
	return z

{{- end }}
}
`
