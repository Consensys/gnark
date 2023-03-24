package gkr

import (
	"github.com/consensys/gnark/std/gkr/snark/polynomial"

	"github.com/consensys/gnark/frontend"
)

// Circuit contains the description of a GKR layer
type Circuit struct {
	Layers []Layer
	BGOut  int
}

// Layer represents a layer of a GKR circuit
type Layer struct {
	DegHL, DegHR, DegHPrime int
	BG                      int
	Gates                   []Gate
	StaticTable             []StaticTableGenerator
}

// Combine returns an evaluation of the GKR layer
func (l *Layer) Combine(
	cs frontend.API,
	q, qPrime, hL, hR, hPrime []frontend.Variable,
	vL, vR frontend.Variable,
) frontend.Variable {
	res := frontend.Variable(0)
	hLhR := append(append([]frontend.Variable{}, hL...), hR...)

	for i := range l.Gates {
		tab := l.StaticTable[i](cs, q)
		res = cs.Add(res, cs.Mul(tab.Eval(cs, hLhR), l.Gates[i](cs, vL, vR)))
	}
	return cs.Mul(res, polynomial.EqEval(cs, qPrime, hPrime))
}

// CombineWithLinearComb returns a linear comb of 2 evaluation of the GKR layer
// for 2 values of q: qL and qR
func (l *Layer) CombineWithLinearComb(
	cs frontend.API,
	qL, qR, qPrime, hL, hR, hPrime []frontend.Variable,
	lambdaL, lambdaR, vL, vR frontend.Variable,
) frontend.Variable {
	res := frontend.Variable(0)
	hLhR := append(append([]frontend.Variable{}, hL...), hR...)

	for i := range l.Gates {
		tabL := l.StaticTable[i](cs, qL)
		tabR := l.StaticTable[i](cs, qR)
		tabEval := cs.Add(
			cs.Mul(lambdaL, tabL.Eval(cs, hLhR)),
			cs.Mul(lambdaR, tabR.Eval(cs, hLhR)),
		)
		res = cs.Add(res, cs.Mul(tabEval, l.Gates[i](cs, vL, vR)))
	}
	return cs.Mul(res, polynomial.EqEval(cs, qPrime, hPrime))
}
