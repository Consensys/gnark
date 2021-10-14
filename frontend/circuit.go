package frontend

import "github.com/consensys/gnark-crypto/ecc"

// Circuit must be implemented by user-defined circuits
//
// the tag format is as follow:
// 		type MyCircuit struct {
// 			Y frontend.Variable `gnark:"name,option"`
// 		}
// if empty, default resolves to variable name (here "Y") and secret visibility
// similarly to json or xml struct tags, these are valid:
// 		`gnark:",public"` or `gnark:"-"`
// using "-" marks the variable as ignored by the Compile method. This can be useful when you need to
// declare variables as aliases that are already allocated. For example
// 		type MyCircuit struct {
// 			Y frontend.Variable `gnark:",public"`
//			Z frontend.Variable `gnark:"-"`
// 		}
// it is then the developer responsability to do circuit.Z = circuit.Y in the Define() method
type Circuit interface {
	// Define declares the circuit's Constraints
	Define(curveID ecc.ID, cs *ConstraintSystem) error
}

// TODO @gbotrel add doc.

type TestableCircuit interface {
	Circuit
	ValidWitnesses(curveID ecc.ID) []Circuit
	InvalidWitnesses(curveID ecc.ID) []Circuit
}

type FuzzableCircuit interface {
	Circuit
	// IsValidWitness --> ensure a fuzzed witness with assign values respect a list of defined properties
	IsValidWitness(curveID ecc.ID) bool
	// optional SeedCorpus() []big.Int
}
