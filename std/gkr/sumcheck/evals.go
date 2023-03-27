package sumcheck

import (
	"github.com/consensys/gnark/std/gkr/circuit"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// GetClaim returns the sum of all evaluations don't call after folding
func (p SingleThreadedProver) GetClaim() fr.Element {

	// Define usefull constants
	n := len(p.eq.Table)         // Number of subcircuit. Since we haven't fold on h' yet
	g := len(p.vL.Table) / n     // SubCircuit size. Since we haven't fold on hR yet
	nGate := len(p.staticTables) // Number of different gates

	var eq, vL, vR, v fr.Element
	var hL, hR, i, h int

	// splitValues[nGate][len(hR) * len(hL)][nEvals]
	// We accumulate the combinators results in this table, by separating the gates
	// We can then avoid a multiplication in the combinator
	splitValues := make([][]fr.Element, nGate)
	staticIsNotZero := make([][]bool, nGate)
	for i = range splitValues {
		splitValues[i] = make([]fr.Element, g*g)
		staticIsNotZero[i] = make([]bool, g*g)
		for h = 0; h < g*g; h++ {
			staticIsNotZero[i][h] = !p.staticTables[i].Table[h].IsZero()
		}
	}

	// Mail loop to accumulate the evaluations in split values
	for hPrime := 0; hPrime < n; hPrime++ {
		eq = p.eq.Table[hPrime]
		for hL = 0; hL < g; hL++ {
			vL = p.vL.Table[hL*n+hPrime]
			for hR = 0; hR < g; hR++ {
				vR = p.vR.Table[hR*n+hPrime]
				for i = 0; i < nGate; i++ {
					if staticIsNotZero[i][hL*g+hR] {
						p.gates[i].Eval(&v, &vL, &vR)
						v.Mul(&v, &eq)
						splitValues[i][hL*g+hR].Add(&splitValues[i][hL*g+hR], &v)
					}
				}
			}
		}
	}

	// Accumulate the values inside the result
	var res fr.Element
	for i := range splitValues {
		for h := range splitValues[i] {
			splitValues[i][h].Mul(&splitValues[i][h], &p.staticTables[i].Table[h])
			res.Add(&res, &v)
		}
	}

	return res
}

// GetEvalsOnHL get the values of the partial on the first variable on hL
func (p SingleThreadedProver) GetEvalsOnHL() []fr.Element {

	// Define usefull constants
	n := len(p.eq.Table)                      // Number of subcircuit. Since we haven't fold on h' yet
	g := len(p.vR.Table) / n                  // SubCircuit size. Since we haven't fold on hR yet
	lenHL := len(p.staticTables[0].Table) / g // Number of remaining variables on R
	nGate := len(p.staticTables)              // Number of different gates
	nEvals := p.degreeHL + 1

	// PreEvaluates the bookKeepingTable so we can reuse them results multiple time later
	evaledStaticTables := make([][][]fr.Element, nGate)
	// staticIsNotZero tracks the values of hL and hR at which the staticTable cancels
	// so that we can avoid computing gates evaluation and multiplying the result by zero after
	staticIsNotZero := make([][]bool, nGate)
	for i, tab := range p.staticTables {
		preEvaluatedStaticTables := tab.FunctionEvals()
		staticIsNotZero[i] = make([]bool, lenHL*g/2)
		evaledStaticTables[i] = make([][]fr.Element, lenHL*g/2)
		for h := range staticIsNotZero[i] {
			staticIsNotZero[i][h] = !(tab.Table[h].IsZero() &&
				preEvaluatedStaticTables[h].IsZero())
			// Computes all the preEvaluations of the staticTables
			evaledStaticTables[i][h] = make([]fr.Element, nEvals)
			evaledStaticTables[i][h][0] = tab.Table[h]
			for t := 1; t < nEvals; t++ {
				evaledStaticTables[i][h][t].Add(
					&evaledStaticTables[i][h][t-1],
					&preEvaluatedStaticTables[h],
				)
			}
		}
	}

	return p.accumulateEvalsOnHL(evaledStaticTables, staticIsNotZero)
}

// GetEvalsOnHR get the values of the partial on the first variable on hR
func (p SingleThreadedProver) GetEvalsOnHR() []fr.Element {
	// Define usefull constants
	n := len(p.eq.Table)         // Number of subcircuit. Since we haven't fold on h' yet
	lenHR := len(p.vR.Table) / n // SubCircuit size. Since we haven't fold on hR yet
	nGate := len(p.staticTables) // Number of different gates
	nEvals := p.degreeHR + 1

	evaledStaticTables := make([][][]fr.Element, nGate)
	// staticIsNotZero tracks the values of hL and hR at which the staticTable cancels
	// so that we can avoid computing gates evaluation and multiplying the result by zero after
	staticIsNotZero := make([][]bool, nGate)
	for i, tab := range p.staticTables {
		preEvaluatedStaticTables := tab.FunctionEvals()
		staticIsNotZero[i] = make([]bool, lenHR/2)
		evaledStaticTables[i] = make([][]fr.Element, lenHR/2)
		for hR := range staticIsNotZero[i] {
			staticIsNotZero[i][hR] = !(tab.Table[hR].IsZero() &&
				preEvaluatedStaticTables[hR].IsZero())
			// Computes all the preEvaluations of the staticTables
			evaledStaticTables[i][hR] = make([]fr.Element, nEvals)
			evaledStaticTables[i][hR][0] = tab.Table[hR]
			for t := 1; t < nEvals; t++ {
				evaledStaticTables[i][hR][t].Add(
					&evaledStaticTables[i][hR][t-1],
					&preEvaluatedStaticTables[hR],
				)
			}
		}
	}

	return p.accumulateEvalsOnHR(staticIsNotZero, evaledStaticTables)
}

// GetEvalsOnHPrime get the values of the partial on the first variable on hPrime
func (p *SingleThreadedProver) GetEvalsOnHPrime() []fr.Element {
	// Define usefull constants
	nGate := len(p.staticTables) // Number of different gates

	// Precomputes the functions evals
	staticTablesVals := make([]fr.Element, nGate)
	for i, tab := range p.staticTables {
		staticTablesVals[i] = tab.Table[0] // The table are already completely folded
	}

	return p.accumulateEvalsOnHPrime(staticTablesVals)
}

func (p SingleThreadedProver) accumulateEvalsOnHL(
	evaledStaticTables [][][]fr.Element,
	staticIsNotZero [][]bool,
) []fr.Element {

	// Define usefull constants
	n := len(p.eq.Table)                      // Number of subcircuit. Since we haven't fold on h' yet
	g := len(p.vR.Table) / n                  // SubCircuit size. Since we haven't fold on hR yet
	lenHL := len(p.staticTables[0].Table) / g // Number of remaining variables on R
	nGate := len(p.staticTables)              // Number of different gates
	nEvals := p.degreeHL + 1
	mid := len(p.vL.Table) / 2

	// Accumulate the evaluations
	evaledVLs := make([]fr.Element, nEvals)
	var evaledEq, deltaVL, evaledVR fr.Element

	// Pre-allocate all the loops variable
	var i, h, hL, hR, t, bVL int
	vS := make([]fr.Element, nEvals)
	var gate circuit.Gate
	var v fr.Element

	// splitValues[nGate][len(hR) * len(hL)][nEvals]
	// We accumulate the combinators results in this table, by separating the gates
	// We can then avoid a multiplication in the combinator
	splitValues := make([][][]fr.Element, nGate)
	for i = range splitValues {
		splitValues[i] = make([][]fr.Element, lenHL*g/2)
		for h = range splitValues[i] {
			splitValues[i][h] = make([]fr.Element, nEvals)
		}
	}

	for hPrime := 0; hPrime < n; hPrime++ {
		evaledEq = p.eq.Table[hPrime] // Keep the value of Eq
		for hL = 0; hL < lenHL/2; hL++ {
			bVL = hL*n + hPrime
			evaledVLs[0] = p.vL.Table[bVL] // Keep the values of VL
			deltaVL.Sub(&p.vL.Table[bVL+mid], &p.vL.Table[bVL])
			for t = 1; t < nEvals; t++ {
				evaledVLs[t].Add(&evaledVLs[t-1], &deltaVL)
			}
			for hR = 0; hR < g; hR++ {
				h = hL*g + hR
				evaledVR = p.vR.Table[hR*n+hPrime] // Keep the values of VR
				for i, gate = range p.gates {
					if staticIsNotZero[i][h] {
						gate.EvalManyVL(vS, evaledVLs, &evaledVR)
						for t, v = range vS {
							// Multply the result by Eq and add it to the splitValues
							// Who accumulates the results
							v.Mul(&v, &evaledEq)
							splitValues[i][h][t].Add(&splitValues[i][h][t], &v)
						}
					}
				}
			}
		}
	}

	// Combine the result to obtain the final response
	res := make([]fr.Element, nEvals)
	for i = range splitValues {
		for h = range splitValues[i] {
			for t, v = range splitValues[i][h] {
				v.Mul(&v, &evaledStaticTables[i][h][t])
				res[t].Add(&res[t], &v)
			}
		}
	}

	return res
}

func (p SingleThreadedProver) accumulateEvalsOnHR(
	staticIsNotZero [][]bool,
	evaledStaticTables [][][]fr.Element,
) []fr.Element {

	// Define usefull constants
	n := len(p.eq.Table)         // Number of subcircuit. Since we haven't fold on h' yet
	lenHR := len(p.vR.Table) / n // SubCircuit size. Since we haven't fold on hR yet
	nGate := len(p.staticTables) // Number of different gates
	nEvals := p.degreeHR + 1
	mid := len(p.vR.Table) / 2
	// Accumulate the evaluations in splitValues
	var evaledEq, evaledVL, deltaVR fr.Element
	evaledVRs := make([]fr.Element, nEvals)

	// Initialize the loop element to reduce the malloc bottleneck
	var i, h, hR, t, bVR int
	var gate circuit.Gate
	vS := make([]fr.Element, nEvals)
	var v fr.Element

	// splitValues[nGate][len(hR) * len(hL)][nEvals]
	// We accumulate the combinators results in this table, by separating the gates
	// We can then avoid a multiplication in the combinator
	splitValues := make([][][]fr.Element, nGate)
	for i = range splitValues {
		splitValues[i] = make([][]fr.Element, lenHR/2)
		for h = range splitValues[i] {
			splitValues[i][h] = make([]fr.Element, nEvals)
		}
	}

	for hPrime := 0; hPrime < n; hPrime++ {
		evaledEq = p.eq.Table[hPrime] // Keep the value of Eq
		evaledVL = p.vL.Table[hPrime] // Keep the values of VL
		for hR = 0; hR < lenHR/2; hR++ {
			bVR = hR*n + hPrime
			evaledVRs[0] = p.vR.Table[bVR]
			deltaVR.Sub(&p.vR.Table[bVR+mid], &p.vR.Table[bVR])
			for t = 1; t < nEvals; t++ {
				evaledVRs[t].Add(&evaledVRs[t-1], &deltaVR)
			}
			for i, gate = range p.gates {
				if staticIsNotZero[i][hR] {
					gate.EvalManyVR(vS, &evaledVL, evaledVRs)
					for t, v = range vS {
						// Multiplies the result by Eq and adds it to the splitValues
						// who accumulates the results
						v.Mul(&v, &evaledEq)
						splitValues[i][hR][t].Add(&splitValues[i][hR][t], &v)
					}
				}
			}
		}
	}

	// Combine the results to form the final response
	res := make([]fr.Element, nEvals)
	for i := range splitValues {
		for h := range splitValues[i] {
			for t := range splitValues[i][h] {
				splitValues[i][h][t].Mul(&splitValues[i][h][t], &evaledStaticTables[i][h][t])
				res[t].Add(&res[t], &splitValues[i][h][t])
			}
		}
	}

	return res
}

func (p SingleThreadedProver) accumulateEvalsOnHPrime(
	staticTablesVals []fr.Element,
) []fr.Element {

	// Define usefull constants
	nGate := len(p.staticTables) // Number of different gates
	nEvals := p.degreeHPrime + 1
	mid := len(p.eq.Table) / 2

	// splitValues[nGate][len(hR) * len(hL)][nEvals]
	// We accumulate the combinators results in this table, by separating the gates
	// We can then avoid a multiplication in the combinator
	splitValues := make([][]fr.Element, nGate)
	for i := range splitValues {
		splitValues[i] = make([]fr.Element, nEvals)
	}

	// Accumulates the combinator's result
	evaledVL := make([]fr.Element, nEvals)
	evaledVR := make([]fr.Element, nEvals)
	evaledEq := make([]fr.Element, nEvals)

	var i, t int
	var v, deltaVL, deltaVR, deltaEq fr.Element
	var gate circuit.Gate

	for hPrime := 0; hPrime < mid; hPrime++ {
		// Computes the preEvaluations
		evaledVL[0] = p.vL.Table[hPrime]
		evaledVR[0] = p.vR.Table[hPrime]
		evaledEq[0] = p.eq.Table[hPrime]

		deltaVL.Sub(&p.vL.Table[hPrime+mid], &p.vL.Table[hPrime])
		deltaVR.Sub(&p.vR.Table[hPrime+mid], &p.vR.Table[hPrime])
		deltaEq.Sub(&p.eq.Table[hPrime+mid], &p.eq.Table[hPrime])

		for t = 1; t < nEvals; t++ {
			evaledVL[t].Add(&evaledVL[t-1], &deltaVL)
			evaledVR[t].Add(&evaledVR[t-1], &deltaVR)
			evaledEq[t].Add(&evaledEq[t-1], &deltaEq)
		}

		for i, gate = range p.gates {
			for t = 0; t < nEvals; t++ {
				gate.Eval(&v, &evaledVL[t], &evaledVR[t])
				v.Mul(&v, &evaledEq[t])
				splitValues[i][t].Add(&splitValues[i][t], &v)
			}
		}
	}

	// Combine the result to obtain the final response
	res := make([]fr.Element, nEvals)
	for i = range splitValues {
		for t, v = range splitValues[i] {
			v.Mul(&v, &staticTablesVals[i])
			res[t].Add(&res[t], &v)
		}
	}

	return res
}
