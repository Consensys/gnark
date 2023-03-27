package circuit

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

// Gate assumes the gate can only have 2 inputs
type Gate interface {
	// ID returns an ID that is unique for the gate
	ID() string
	// GnarkEval performs the same computation as Eval but on Gnark variables
	GnarkEval(cs frontend.API, vL, vR frontend.Variable) frontend.Variable
	// Eval returns an evaluation for a unique pair of Eval
	Eval(res, vL, vR *fr.Element)
	// EvalManyVL returns multiple evaluations with the same vR
	EvalManyVL(res, vLs []fr.Element, vR *fr.Element)
	// EvalManyVR returns multiple evaluations with the same vL
	EvalManyVR(res []fr.Element, vL *fr.Element, vRs []fr.Element)
	// Degrees returns the degrees of the gate relatively to HL, HR, HPrime
	Degrees() (degHL, degHR, degHPrime int)
}

// EvaluateCombinator evaluate eq * \sum_i{ statics_i * gates_i(vL, vR) }
func EvaluateCombinator(vL, vR, eq *fr.Element, gates []Gate, statics []fr.Element) fr.Element {
	var tmp, res fr.Element
	for i := range gates {
		gates[i].Eval(&tmp, vL, vR)
		tmp.Mul(&statics[i], &tmp)
		res.Add(&res, &tmp)
	}
	res.Mul(&res, eq)
	return res
}

// AddGate performs an addition
type AddGate struct{}

// ID returns the gate ID
func (a AddGate) ID() string { return "AddGate" }

// Eval return the result vL + vR
func (a AddGate) Eval(res, vL, vR *fr.Element) {
	res.Add(vL, vR)
}

// GnarkEval compute the gate on a gnark circuit
func (a AddGate) GnarkEval(cs frontend.API, vL, vR frontend.Variable) frontend.Variable {
	// Unoptimized, but unlikely to cause any significant performance loss
	return cs.Add(vL, vR)
}

// EvalManyVR performs an element-wise addition of many vRs values by one vL value
// res must be initialized with the same size as vRs
func (a AddGate) EvalManyVR(res []fr.Element, vL *fr.Element, vRs []fr.Element) {
	for i := range vRs {
		res[i].Add(vL, &vRs[i])
	}
}

// EvalManyVL performs an element-wise addition of many vLs values by one vR value
func (a AddGate) EvalManyVL(res []fr.Element, vLs []fr.Element, vR *fr.Element) {
	for i := range vLs {
		res[i].Add(&vLs[i], vR)
	}
}

// Degrees returns the degrees of the gate on hL, hR and hPrime
func (a AddGate) Degrees() (degHL, degHR, degHPrime int) {
	return 1, 1, 1
}

// MulGate performs a multiplication
type MulGate struct{}

// ID returns the MulGate as ID
func (m MulGate) ID() string { return "MulGate" }

// Eval returns vL * vR
func (m MulGate) Eval(res, vL, vR *fr.Element) {
	res.Mul(vL, vR)
}

// GnarkEval performs the gate operation on gnark variables
func (m MulGate) GnarkEval(cs frontend.API, vL, vR frontend.Variable) frontend.Variable {
	return cs.Mul(vL, vR)
}

// EvalManyVR performs an element-wise multiplication of many vRs values by one vL value
func (m MulGate) EvalManyVR(res []fr.Element, vL *fr.Element, vRs []fr.Element) {
	for i := range vRs {
		res[i].Mul(vL, &vRs[i])
	}
}

// EvalManyVL performs an element-wise multiplication of many vLs values by one vR value
func (m MulGate) EvalManyVL(res, vLs []fr.Element, vR *fr.Element) {
	for i := range vLs {
		res[i].Mul(&vLs[i], vR)
	}
}

// Degrees returns the degrees of the gate on hL, hR and hPrime
func (m MulGate) Degrees() (degHL, degHR, degHPrime int) {
	return 1, 1, 2
}

// CopyGate performs a copy of the vL value and ignores the vR value
type CopyGate struct{}

// ID returns "CopyGate" as an ID for CopyGate
func (c CopyGate) ID() string { return "CopyGate" }

// Eval returns vL
func (c CopyGate) Eval(res, vL, vR *fr.Element) {
	res.Set(vL)
	// *res = vL
}

// GnarkEval performs the copy on gnark variable
func (c CopyGate) GnarkEval(cs frontend.API, vL, vR frontend.Variable) frontend.Variable {
	return vL
}

// EvalManyVR performs an element-wise copy of vL for many vRs. (ignoring the values of the vRs)
func (c CopyGate) EvalManyVR(res []fr.Element, vL *fr.Element, vRs []fr.Element) {
	for i := range vRs {
		res[i].Set(vL)
	}
}

// EvalManyVL performs an element-wise copy of many vLs values
func (c CopyGate) EvalManyVL(res, vLs []fr.Element, vR *fr.Element) {
	copy(res, vLs)
}

// Degrees returns the degrees of the gate on hL, hR and hPrime
func (c CopyGate) Degrees() (degHL, degHR, degHPrime int) {
	return 1, 0, 1
}

// CipherGate cipher gate returns vL + (vR + c)^7
type CipherGate struct {
	Ark fr.Element
}

// NewCipherGate construct a new cipher gate given an ark
func NewCipherGate(ark fr.Element) *CipherGate {
	return &CipherGate{Ark: ark}
}

// ID returns the id of the cipher gate and print the ark as well
func (c *CipherGate) ID() string { return fmt.Sprintf("CipherGate-%v", c.Ark.String()) }

// Eval returns vL + (vR + c)^7
func (c *CipherGate) Eval(res, vL, vR *fr.Element) {
	// tmp = vR + Ark
	var tmp fr.Element
	tmp.Add(vR, &c.Ark)
	// res = tmp^7
	res.Square(&tmp)
	res.Mul(res, &tmp)
	res.Square(res)
	res.Mul(res, &tmp)
	// Then add vL
	res.Add(res, vL)
}

// GnarkEval performs the cipher operation on gnark variables
func (c *CipherGate) GnarkEval(cs frontend.API, vL, vR frontend.Variable) frontend.Variable {
	tmp := cs.Add(vR, c.Ark)
	cipher := cs.Mul(tmp, tmp)
	cipher = cs.Mul(cipher, tmp)
	cipher = cs.Mul(cipher, cipher)
	cipher = cs.Mul(cipher, tmp)
	return cs.Add(cipher, vL)
}

// EvalManyVR performs cipher evaluations of many vRs values by one vL value
// Nothing special to do here
func (c *CipherGate) EvalManyVR(res []fr.Element, vL *fr.Element, vRs []fr.Element) {
	var tmp fr.Element
	for i := 0; i < len(vRs); i++ {
		// tmp = vR + Ark
		tmp.Add(&vRs[i], &c.Ark)
		// res = tmp^7
		res[i].Square(&tmp)
		res[i].Mul(&res[i], &tmp)
		res[i].Square(&res[i])
		res[i].Mul(&res[i], &tmp)
		// Then add vL
		res[i].Add(&res[i], vL)
	}
}

// EvalManyVL performs an element-wise cipher of many vLs values by one vR
// This one is optimized to only do the vL exponentiation once
func (c *CipherGate) EvalManyVL(res, vLs []fr.Element, vR *fr.Element) {
	// tmp = vR + Ark
	var tmp, right fr.Element
	tmp.Add(vR, &c.Ark)
	// right = tmp^7
	right.Square(&tmp)
	right.Mul(&right, &tmp)
	right.Square(&right)
	right.Mul(&right, &tmp)

	for i := 0; i < len(vLs); i++ {
		res[i].Add(&right, &vLs[i])
	}
}

// Degrees returns the degrees of the gate on hL, hR and hPrime
func (c *CipherGate) Degrees() (degHL, degHR, degHPrime int) {
	return 1, 7, 7
}
