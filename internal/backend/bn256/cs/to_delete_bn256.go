package cs

import (
	"fmt"
	"strconv"

	"github.com/consensys/gnark/internal/backend/compiled"
)

func printTermPCSBn256(pcs *SparseR1CS, t compiled.Term) string {

	res := ""
	if t == 0 {
		return res
	}
	id := t.VariableID()
	cID := t.CoeffID()
	coef := pcs.Coeffs[cID]
	res += coef.String()
	res += "*"
	res += strconv.Itoa(id)
	res += ":"
	switch t.VariableVisibility() {
	case compiled.Internal:
		res += "i"
	case compiled.Public:
		res += "p"
	case compiled.Secret:
		res += "s"
	}
	res += " "
	return res
}

func printSparseR1CBn256(pcs *SparseR1CS, plk compiled.SparseR1C) string {
	res := ""
	res += printTermPCSBn256(pcs, plk.L)
	res += " + "
	res += printTermPCSBn256(pcs, plk.R)
	res += " + ("
	res += printTermPCSBn256(pcs, plk.M[0])
	res += " )*( "
	res += printTermPCSBn256(pcs, plk.M[1])
	res += ") + "
	res += printTermPCSBn256(pcs, plk.O)
	res += " + "
	res += pcs.Coeffs[plk.K].String()
	res += " = 0"
	return res
}

func PrintPCSBn256(pcs *SparseR1CS) string {
	//pcs := _pcs.(*SparseR1CS)
	res := "constraints:\n"
	for i := 0; i < len(pcs.Constraints); i++ {
		res += printSparseR1CBn256(pcs, pcs.Constraints[i])
		res += "\n"
	}
	res += "assertions:\n"
	for i := 0; i < len(pcs.Assertions); i++ {
		res += printSparseR1CBn256(pcs, pcs.Assertions[i])
		res += "\n"
	}
	nbConstraints := fmt.Sprintf("nb constraints: %d\n", len(pcs.Constraints))
	res += nbConstraints
	nbAssertions := fmt.Sprintf("nb assertions: %d\n", len(pcs.Assertions))
	res += nbAssertions
	res += "\n"
	return res
}

func PrintPlonkDigestBn256(pcs *SparseR1CS) string {
	//pcs := _pcs.(*SparseR1CS)
	qL := "qL = [ "
	qR := "qR = [ "
	qO := "qO = [ "
	qM := "qM = [ "
	qK := "qK = [ "
	for i := 0; i < len(pcs.Constraints); i++ {
		plk := pcs.Constraints[i]
		lCoef := pcs.Coeffs[plk.L.CoeffID()]
		qL += lCoef.String()
		qL += " , "

		rCoef := pcs.Coeffs[plk.R.CoeffID()]
		qR += rCoef.String()
		qR += " , "

		oCoef := pcs.Coeffs[plk.O.CoeffID()]
		qO += oCoef.String()
		qO += " , "

		mCoef := pcs.Coeffs[plk.M[0].CoeffID()]
		_mCoef := pcs.Coeffs[plk.M[1].CoeffID()]
		mCoef.Mul(&mCoef, &_mCoef)
		qM += mCoef.String()
		qM += " , "

		kCoef := pcs.Coeffs[plk.K]
		qK += kCoef.String()
		qK += " , "
	}
	for i := 0; i < len(pcs.Assertions); i++ {
		plk := pcs.Assertions[i]

		lCoef := pcs.Coeffs[plk.L.CoeffID()]
		qL += lCoef.String()
		qL += " , "

		rCoef := pcs.Coeffs[plk.R.CoeffID()]
		qR += rCoef.String()
		qR += " , "

		oCoef := pcs.Coeffs[plk.O.CoeffID()]
		qO += oCoef.String()
		qO += " , "

		mCoef := pcs.Coeffs[plk.M[0].CoeffID()]
		_mCoef := pcs.Coeffs[plk.M[1].CoeffID()]
		mCoef.Mul(&mCoef, &_mCoef)
		qM += mCoef.String()
		qM += " , "

		kCoef := pcs.Coeffs[plk.K]
		qK += kCoef.String()
		qK += " , "
	}
	qL += " ]\n"
	qR += " ]\n"
	qO += " ]\n"
	qM += " ]\n"
	qK += " ]\n"
	res := qL + qR + qO + qM + qK
	return res
}
