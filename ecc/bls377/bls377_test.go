package bls377

import (
	"testing"

	"github.com/consensys/gnark/ecc/bls377/fr"
)

var _ = BLS377()

func TestScalarMulG1Jac(t *testing.T) {

	curve := BLS377()
	scalar := fr.Element{11478714, 134994, 32382983, 0}
	res := &G1Jac{}

	res.ScalarMulByGen(curve, scalar)
	// curve.ScalarMulG1Jac(scalar[:], res)

	var expectedRes G1Jac
	expectedRes.X.SetString("136454298639670595017792256537858574477891352777404060873084444956653358257085713891474246269620669815371255948339")
	expectedRes.Y.SetString("205194473026467452041773093045727887585682153049354947593796836537337558204088660850453307574265860389073016364185")
	expectedRes.Z.SetString("1")

	if !res.Equal(&expectedRes) {
		t.Error("Error ScalarMulG1Jac")
	}
}

func TestScalarMulG2Jac(t *testing.T) {

	curve := BLS377()
	scalar := [4]uint64{11478714, 134994, 32382983, 0}

	res := &G2Jac{}
	res.ScalarMulByGen(curve, scalar)

	var expectedRes G2Jac
	expectedRes.X.SetString("86789175449287031514467196543362945873832770272666013559778588314762291790569405082910942609097010223449648982046",
		"182044243022972173371877627766351706206840084486002767615102619557088842655910707433554609083288883445064733300371")
	expectedRes.Y.SetString("254486830160201200386413919100870915301502097540744973621378233133361589335938892820613468371382696287840411041028",
		"122425666570863790805270250720283482242962043862904378442212185350638555822539460402116739342380399027855346787624")
	expectedRes.Z.SetString("1", "0")

	if !res.Equal(&expectedRes) {
		t.Error("Error ScalarMulG1Jac")
	}
}

//--------------------//
//     benches		  //
//--------------------//

func BenchmarkScalarMulG1Jac(b *testing.B) {
	curve := BLS377()
	scalar := [4]uint64{11478714, 134994, 32382983, 0}
	res := &G1Jac{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res.ScalarMulByGen(curve, scalar)
	}
}

func BenchmarkScalarMulG2Jac(b *testing.B) {
	curve := BLS377()
	scalar := [4]uint64{11478714, 134994, 32382983, 0}
	res := &G2Jac{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res.ScalarMulByGen(curve, scalar)
	}
}

func BenchmarkScalarMul(b *testing.B) {

	curve := BLS377()

	var expo fr.Element
	expo.SetString("11019358103200512606383071234864109998742382266").FromMont()

	G := curve.g2Gen.Clone()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		G.ScalarMul(curve, G, expo)
	}
}
