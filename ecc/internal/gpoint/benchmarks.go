package gpoint

const benchmarks = `

//--------------------//
//     benches		  //
//--------------------//

var benchRes{{.Name}} {{.Name}}Jac

func Benchmark{{.Name}}ScalarMul(b *testing.B) {

	curve := {{toUpper .PackageName}}()
	p := testPoints{{.Name}}()

	var scalar fr.Element
	scalar.SetRandom()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p[1].ScalarMul(curve, &p[1], scalar)
		b.StopTimer()
		scalar.SetRandom()
		b.StartTimer()
	}

}

func Benchmark{{.Name}}Add(b *testing.B) {

	curve := {{toUpper .PackageName}}()
	p := testPoints{{.Name}}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchRes{{.Name}}  = p[1]
		benchRes{{.Name}} .Add(curve, &p[2])
	}

}

func Benchmark{{.Name}}AddMixed(b *testing.B) {

	p := testPoints{{.Name}}()
	_p2 := {{.Name}}Affine{}
	p[2].ToAffineFromJac(&_p2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchRes{{.Name}} = p[1]
		benchRes{{.Name}} .AddMixed(&_p2)
	}


}

func Benchmark{{.Name}}Double(b *testing.B) {

	p := testPoints{{.Name}}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchRes{{.Name}} = p[1]
		benchRes{{.Name}}.Double()
	}

}

func Benchmark{{.Name}}WindowedMultiExp(b *testing.B) {
	curve := {{toUpper .PackageName}}()

	var G {{.Name}}Jac

	var mixer fr.Element
	mixer.SetString("7716837800905789770901243404444209691916730933998574719964609384059111546487")

	var nbSamples int
	nbSamples = 400000

	samplePoints := make([]{{.Name}}Jac, nbSamples)
	sampleScalars := make([]fr.Element, nbSamples)

	G.Set(&curve.{{toLower .Name}}Gen)

	for i := 1; i <= nbSamples; i++ {
		sampleScalars[i-1].SetUint64(uint64(i)).
			Mul(&sampleScalars[i-1], &mixer).
			FromMont()
		samplePoints[i-1].Set(&curve.{{toLower .Name}}Gen)
	}

	var testPoint {{.Name}}Jac

	for i := 0; i < 8; i++ {
		b.Run(fmt.Sprintf("%d points", (i+1)*50000), func(b *testing.B) {
			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				testPoint.WindowedMultiExp(curve, samplePoints[:50000+i*50000], sampleScalars[:50000+i*50000])
			}
		})
	}
}

func BenchmarkMultiExp{{.Name}}(b *testing.B) {

	curve := {{toUpper .PackageName}}()

	var G {{.Name}}Jac

	var mixer fr.Element
	mixer.SetString("7716837800905789770901243404444209691916730933998574719964609384059111546487")

	var nbSamples int
	nbSamples = 800000

	samplePoints := make([]{{.Name}}Affine, nbSamples)
	sampleScalars := make([]fr.Element, nbSamples)

	G.Set(&curve.{{toLower .Name}}Gen)

	for i := 1; i <= nbSamples; i++ {
		sampleScalars[i-1].SetUint64(uint64(i)).
			Mul(&sampleScalars[i-1], &mixer).
			FromMont()
		G.ToAffineFromJac(&samplePoints[i-1])
	}

	var testPoint {{.Name}}Jac

	for i := 0; i < 16; i++ {
		b.Run(fmt.Sprintf("former (%d points)", (i+1)*50000), func(b *testing.B) {
			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				<-testPoint.MultiExpFormer(curve, samplePoints[:50000+i*50000], sampleScalars[:50000+i*50000])
			}
		})
		b.Run(fmt.Sprintf("new (%d points)", (i+1)*50000), func(b *testing.B) {
			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				<-testPoint.MultiExp(curve, samplePoints[:50000+i*50000], sampleScalars[:50000+i*50000])
			}
		})
	}
}
		
`
