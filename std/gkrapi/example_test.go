package gkrapi_test

import (
	"encoding/binary"
	"errors"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/constraint/solver/gkrgates"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkr"
	"github.com/consensys/gnark/std/gkrapi"
	stdHash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

func Example() {
	// This example computes the double of multiple BLS12-377 G1 points, which can be computed natively over BW6-761.
	// This means that the imported fr and fp packages are the same, being from BW6-761 and BLS12-377 respectively. TODO @Tabaie delete if no longer have fp imported
	// It is based on the function DoubleAssign() of type G1Jac in gnark-crypto v0.17.0.
	// github.com/consensys/gnark-crypto/ecc/bls12-377
	const fsHashName = "MIMC"

	// register the gates: Doing so is not needed here because
	// the proof is being computed in the same session as the
	// SNARK circuit being compiled.
	// But in production applications it would be necessary.

	assertNoError(gkrgates.Register(squareGate, 1))
	assertNoError(gkrgates.Register(sGate, 4))
	assertNoError(gkrgates.Register(zGate, 4))
	assertNoError(gkrgates.Register(xGate, 2))
	assertNoError(gkrgates.Register(yGate, 4))

	const nbInstances = 2
	// create instances
	assignment := exampleCircuit{
		X:    make([]frontend.Variable, nbInstances),
		Y:    make([]frontend.Variable, nbInstances),
		Z:    make([]frontend.Variable, nbInstances),
		XOut: make([]frontend.Variable, nbInstances),
		YOut: make([]frontend.Variable, nbInstances),
		ZOut: make([]frontend.Variable, nbInstances),
	}

	for i := range nbInstances {
		// create a "random" point
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(i))
		a, err := bls12377.HashToG1(b[:], nil)
		assertNoError(err)
		var p bls12377.G1Jac
		p.FromAffine(&a)

		assignment.X[i] = p.X
		assignment.Y[i] = p.Y
		assignment.Z[i] = p.Z

		p.DoubleAssign()
		assignment.XOut[i] = p.X
		assignment.YOut[i] = p.Y
		assignment.ZOut[i] = p.Z
	}

	circuit := exampleCircuit{
		X:          make([]frontend.Variable, nbInstances),
		Y:          make([]frontend.Variable, nbInstances),
		Z:          make([]frontend.Variable, nbInstances),
		XOut:       make([]frontend.Variable, nbInstances),
		YOut:       make([]frontend.Variable, nbInstances),
		ZOut:       make([]frontend.Variable, nbInstances),
		fsHashName: fsHashName,
	}

	assertNoError(test.IsSolved(&circuit, &assignment, ecc.BW6_761.ScalarField()))

	// Output:
}

type exampleCircuit struct {
	X, Y, Z          []frontend.Variable // Jacobian coordinates for each point (input)
	XOut, YOut, ZOut []frontend.Variable // Jacobian coordinates for the double of each point (expected output)
	fsHashName       string              // name of the hash function used for Fiat-Shamir in the GKR verifier
}

func (c *exampleCircuit) Define(api frontend.API) error {
	if len(c.X) != len(c.Y) || len(c.X) != len(c.Z) || len(c.X) != len(c.XOut) || len(c.X) != len(c.YOut) || len(c.X) != len(c.ZOut) {
		return errors.New("all inputs/outputs must have the same length (i.e. the number of instances)")
	}

	gkrApi := gkrapi.New()

	// create GKR circuit variables based on the given assignments
	X, err := gkrApi.Import(c.X)
	if err != nil {
		return err
	}

	Y, err := gkrApi.Import(c.Y)
	if err != nil {
		return err
	}

	Z, err := gkrApi.Import(c.Z)
	if err != nil {
		return err
	}

	XX := gkrApi.Gate(squareGate, X)    // 405: XX.Square(&p.X)
	YY := gkrApi.Gate(squareGate, Y)    // 406: YY.Square(&p.Y)
	YYYY := gkrApi.Gate(squareGate, YY) // 407: YYYY.Square(&YY)
	ZZ := gkrApi.Gate(squareGate, Z)    // 408: ZZ.Square(&p.Z)

	S := gkrApi.Gate(sGate, X, YY, XX, YYYY) // 409 - 413

	// 414: M.Double(&XX).Add(&M, &XX)
	// Note (but don't explicitly compute) that M = 3XX

	Z = gkrApi.Gate(zGate, Z, Y, YY, ZZ)   // 415 - 418
	X = gkrApi.Gate(xGate, XX, S)          // 419-422
	Y = gkrApi.Gate(yGate, S, X, XX, YYYY) // 423 - 426

	// have to duplicate X for it to be considered an output variable
	X = gkrApi.NamedGate(gkr.Identity, X)

	// register the hash function used for verification (fiat shamir)
	stdHash.Register(c.fsHashName, func(api frontend.API) (stdHash.FieldHasher, error) {
		m, err := mimc.NewMiMC(api)
		return &m, err
	})

	// solve and prove the circuit
	solution, err := gkrApi.Solve(api)
	if err != nil {
		return err
	}

	// check the output

	XOut := solution.Export(X)
	YOut := solution.Export(Y)
	ZOut := solution.Export(Z)
	for i := range XOut {
		api.AssertIsEqual(XOut[i], c.XOut[i])
		api.AssertIsEqual(YOut[i], c.YOut[i])
		api.AssertIsEqual(ZOut[i], c.ZOut[i])
	}

	challenges := make([]frontend.Variable, 0, len(c.X)*6)
	challenges = append(challenges, XOut...)
	challenges = append(challenges, YOut...)
	challenges = append(challenges, ZOut...)
	challenges = append(challenges, c.X...)
	challenges = append(challenges, c.Y...)
	challenges = append(challenges, c.Z...)

	challenge, err := api.(frontend.Committer).Commit(challenges...)
	if err != nil {
		return err
	}

	// verify the proof
	return solution.Verify(c.fsHashName, challenge)
}

// custom gates

// squareGate x -> x²
func squareGate(api gkr.GateAPI, input ...frontend.Variable) frontend.Variable {
	return api.Mul(input[0], input[0])
}

// sGate combines the operations that define the first value assigned to variable S.
// input = [X, YY, XX, YYYY].
// S = 2 * [(X + YY)² - XX - YYYY].
func sGate(api gkr.GateAPI, input ...frontend.Variable) (S frontend.Variable) {
	S = api.Add(input[0], input[1])    // 409: S.Add(&p.X, &YY)
	S = api.Mul(S, S)                  // 410: S.Square(&S).
	S = api.Sub(S, input[2], input[3]) // 411: Sub(&S, &XX).
	//                                    412: Sub(&S, &YYYY).
	return api.Add(S, S) // 413: Double(&S)
}

// zGate combines the operations that define the assignment to p.Z.
// input = [p.Z, p.Y, YY, ZZ].
// p.Z = (p.Z + p.Y)² - YY - ZZ.
func zGate(api gkr.GateAPI, input ...frontend.Variable) (Z frontend.Variable) {
	Z = api.Add(input[0], input[1])    // 415: p.Z.Add(&p.Z, &p.Y).
	Z = api.Mul(Z, Z)                  // 416: p.Z.Square(&p.Z).
	Z = api.Sub(Z, input[2], input[3]) // 417: Sub(&p.Z, &YY).
	//                                    418: Sub(&p.Z, &ZZ)
	return
}

// xGate combines the operations that define the assignment to p.X.
// input = [XX, S].
// p.X = 9XX² - 2S.
func xGate(api gkr.GateAPI, input ...frontend.Variable) (X frontend.Variable) {
	M := api.Mul(input[0], 3)            // 414: M.Double(&XX).Add(&M, &XX)
	T := api.Mul(M, M)                   //     419: T.Square(&M)
	X = api.Sub(T, api.Mul(input[1], 2)) // 420: p.X = T
	//                                          421: T.Double(&S)
	//                                          422: p.X.Sub(&p.X, &T)
	return
}

// yGate combines the operations that define the assignment to p.Y.
// input = [S, p.X, XX, YYYY].
// p.Y = (S - p.X) * 3 * XX - 8 * YYYY.
func yGate(api gkr.GateAPI, input ...frontend.Variable) (Y frontend.Variable) {
	Y = api.Sub(input[0], input[1]) //         423: p.Y.Sub(&S, &p.X).
	Y = api.Mul(Y, input[2], 3)     //    414: M.Double(&XX).Add(&M, &XX)
	//                                         424:Mul(&p.Y, &M)
	Y = api.Sub(Y, api.Mul(input[3], 8)) // 425: YYYY.Double(&YYYY).Double(&YYYY).Double(&YYYY)
	//                                         426: p.Y.Sub(&p.Y, &YYYY)

	return
}

func assertNoError(err error) {
	if err != nil {
		panic(err)
	}
}
