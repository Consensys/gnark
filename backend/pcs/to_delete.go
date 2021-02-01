package pcs

import (
	"fmt"
	"strconv"

	"github.com/consensys/gnark/backend"
)

func printTermPCS(pcs *UntypedPlonkCS, t backend.Term) string {

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
	case backend.Internal:
		res += "i"
	case backend.Public:
		res += "p"
	case backend.Secret:
		res += "s"
	}
	res += " "
	return res
}

func printPlonkConstraint(pcs *UntypedPlonkCS, plk backend.PlonkConstraint) string {
	res := ""
	res += printTermPCS(pcs, plk.L)
	res += " + "
	res += printTermPCS(pcs, plk.R)
	res += " + ("
	res += printTermPCS(pcs, plk.M[0])
	res += " )*( "
	res += printTermPCS(pcs, plk.M[1])
	res += ") + "
	res += printTermPCS(pcs, plk.O)
	res += " + "
	res += strconv.Itoa(plk.K)
	res += " = 0"
	return res
}

func PrintPCS(_pcs CS) string {
	pcs := _pcs.(*UntypedPlonkCS)
	res := "constraints:\n"
	for i := 0; i < len(pcs.Constraints); i++ {
		res += printPlonkConstraint(pcs, pcs.Constraints[i])
		res += "\n"
	}
	res += "assertions:\n"
	for i := 0; i < len(pcs.Assertions); i++ {
		res += printPlonkConstraint(pcs, pcs.Assertions[i])
		res += "\n"
	}
	nbConstraints := fmt.Sprintf("nb constraints: %d\n", len(pcs.Constraints))
	res += nbConstraints
	nbAssertions := fmt.Sprintf("nb assertions: %d\n", len(pcs.Assertions))
	res += nbAssertions
	res += "\n"
	return res
}

func PrintPlonkDigest(_pcs CS) string {
	pcs := _pcs.(*UntypedPlonkCS)
	qL := "qL = [ "
	qR := "qR = [ "
	qO := "qO = [ "
	qM := "qM = [ "
	qK := "qK = [ "
	for i := 0; i < len(pcs.Constraints); i++ {
		plk := pcs.Constraints[i]
		lCoef := pcs.Coeffs[plk.L.CoeffID()]
		qL += lCoef.String()
		qL += " + "

		rCoef := pcs.Coeffs[plk.R.CoeffID()]
		qR += rCoef.String()
		qR += " + "

		oCoef := pcs.Coeffs[plk.O.CoeffID()]
		qO += oCoef.String()
		qO += " + "

		mCoef := pcs.Coeffs[plk.M[0].CoeffID()]
		_mCoef := pcs.Coeffs[plk.M[1].CoeffID()]
		mCoef.Mul(&mCoef, &_mCoef)
		qM += mCoef.String()
		qM += " + "

		kCoef := pcs.Coeffs[plk.K]
		qK += kCoef.String()
		qK += " + "
	}
	for i := 0; i < len(pcs.Assertions); i++ {
		plk := pcs.Assertions[i]

		lCoef := pcs.Coeffs[plk.L.CoeffID()]
		qL += lCoef.String()
		qL += " + "

		rCoef := pcs.Coeffs[plk.R.CoeffID()]
		qR += rCoef.String()
		qR += " + "

		oCoef := pcs.Coeffs[plk.O.CoeffID()]
		qO += oCoef.String()
		qO += " + "

		mCoef := pcs.Coeffs[plk.M[0].CoeffID()]
		_mCoef := pcs.Coeffs[plk.M[1].CoeffID()]
		mCoef.Mul(&mCoef, &_mCoef)
		qM += mCoef.String()
		qM += " + "

		kCoef := pcs.Coeffs[plk.K]
		qK += kCoef.String()
		qK += " + "
	}
	qL += " ]\n"
	qR += " ]\n"
	qO += " ]\n"
	qM += " ]\n"
	qK += " ]\n"
	res := qL + qR + qO + qM + qK
	return res
}
