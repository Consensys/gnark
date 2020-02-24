package gpoint

const benchmarks = `

//--------------------//
//     benches		  //
//--------------------//

var benchRes{{.Name}} {{.Name}}Jac

{{- if ne .Name "G2"}} 
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
{{- end }}

func Benchmark{{.Name}}WindowedMultiExp(b *testing.B) {
	curve := {{toUpper .PackageName}}()

	var numPoints []int
	for n := 5; n < 400000; n*=2 {
		numPoints = append(numPoints, n)
	}

	for j := range numPoints {
		points, scalars := testPoints{{.Name}}MultiExp(numPoints[j])

		b.Run(fmt.Sprintf("%d points", numPoints[j]), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				benchRes{{.Name}}.WindowedMultiExp(curve, points, scalars)
			}
		})
	}
}

func Benchmark{{.Name}}MultiExp(b *testing.B) {
	curve := {{toUpper .PackageName}}()

	var numPoints []int
	for n := 5; n < 400000; n*=2 {
		numPoints = append(numPoints, n)
	}
	
	for j := range numPoints {
		_points, scalars := testPoints{{.Name}}MultiExp(numPoints[j])
		points := make([]{{.Name}}Affine, len(_points))
		for i := 0; i < len(_points); i++ {
			_points[i].ToAffineFromJac(&points[i])
		}

		b.Run(fmt.Sprintf("%d points", numPoints[j]), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				benchRes{{.Name}}.MultiExp(curve, points, scalars)
			}
		})
	}
}

		
`
