package test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/plonkfri"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

type _witness struct {
	full       witness.Witness
	public     witness.Witness
	assignment frontend.Circuit
}

func (assert *Assert) parseAssignment(circuit frontend.Circuit, assignment frontend.Circuit, curve ecc.ID, serializationCheck bool) _witness {
	if assignment == nil {
		return _witness{}
	}
	full, err := frontend.NewWitness(assignment, curve.ScalarField())
	assert.NoError(err, "can't parse assignment into full witness")

	public, err := frontend.NewWitness(assignment, curve.ScalarField(), frontend.PublicOnly())
	assert.NoError(err, "can't parse assignment into public witness")

	if serializationCheck {
		assert.Run(func(assert *Assert) {
			assert.marshalWitness(full, curve, false)
		}, curve.String(), "marshal/binary")
		assert.Run(func(assert *Assert) {
			assert.marshalWitness(public, curve, true)
		}, curve.String(), "marshal-public/binary")

		assert.Run(func(assert *Assert) {
			s := lazySchema(circuit)()
			assert.marshalWitnessJSON(full, s, curve, false)
		}, curve.String(), "marshal/json")
		assert.Run(func(assert *Assert) {
			s := lazySchema(circuit)()
			assert.marshalWitnessJSON(public, s, curve, true)
		}, curve.String(), "marshal-public/json")
	}

	return _witness{full: full, public: public, assignment: assignment}
}

func (assert *Assert) CheckCircuit(circuit frontend.Circuit, opts ...TestingOption) {
	// get the testing configuration
	opt := assert.options(opts...)

	assert.Run(func(assert *Assert) {

		// for each {curve, backend} tuple
		for _, curve := range opt.Curves {
			curve := curve

			// parse valid / invalid assignments
			var invalidWitnesses, validWitnesses []_witness
			for _, a := range opt.validAssignments {
				w := assert.parseAssignment(circuit, a, curve, opt.WitnessSerialization)
				validWitnesses = append(validWitnesses, w)

				// check that the assignment is valid with the test engine
				// assert.checkError(err, b, curve, w.full, lazySchema(circuit))
				err := IsSolved(circuit, w.assignment, curve.ScalarField())
				assert.NoError(err)
			}

			for _, a := range opt.invalidAssignments {
				w := assert.parseAssignment(circuit, a, curve, opt.WitnessSerialization)
				invalidWitnesses = append(invalidWitnesses, w)

				// check that the assignment is invalid with the test engine
				err := IsSolved(circuit, w.assignment, curve.ScalarField())
				assert.Error(err)
			}

			// for each backend; compile, prove/verify or solve, check serialization if needed.
			for _, b := range opt.Backends {
				b := b
				assert.Run(func(assert *Assert) {
					// 1- check that the circuit compiles
					ccs, err := assert.compile(circuit, curve, b, opt.compileOpts)
					assert.checkError(err, b, curve, nil, nil)

					// TODO @gbotrel check serialization round trip with constraint system.

					// 2- if we are not running the full prover;
					// we need to run the solver on the constraint system only
					if !opt.FullProver {
						for _, w := range invalidWitnesses {
							assert.Run(func(assert *Assert) {
								assert.t.Parallel()
								_, err = ccs.Solve(w.full, opt.solverOpts...)
								assert.mustError(err, b, curve, w.full, lazySchema(circuit))
							}, "invalid_witness", curve.String(), b.String())
						}

						for _, w := range validWitnesses {
							assert.Run(func(assert *Assert) {
								assert.t.Parallel()
								_, err = ccs.Solve(w.full, opt.solverOpts...)
								assert.checkError(err, b, curve, w.full, lazySchema(circuit))
							}, "valid_witness", curve.String(), b.String())
						}

						return
					}

					// we need to run the setup, prove and verify and check serialization
					assert.t.Parallel()
					type fnSetup func(ccs constraint.ConstraintSystem) (
						pk, vk any,
						pkBuilder, vkBuilder, proofBuilder func() any,
						err error)
					type fnProve func(ccs constraint.ConstraintSystem, pk any, fullWitness witness.Witness, opts ...backend.ProverOption) (proof any, err error)
					type fnVerify func(proof, vk any, publicWitness witness.Witness) error

					var setup fnSetup
					var prove fnProve
					var verify fnVerify

					switch b {
					case backend.GROTH16:
						setup = func(ccs constraint.ConstraintSystem) (
							pk, vk any,
							pkBuilder, vkBuilder, proofBuilder func() any,
							err error) {
							pk, vk, err = groth16.Setup(ccs)
							return pk, vk, func() any { return groth16.NewProvingKey(curve) }, func() any { return groth16.NewVerifyingKey(curve) }, func() any { return groth16.NewProof(curve) }, err
						}
						prove = func(ccs constraint.ConstraintSystem, pk any, fullWitness witness.Witness, opts ...backend.ProverOption) (proof any, err error) {
							return groth16.Prove(ccs, pk.(groth16.ProvingKey), fullWitness, opts...)
						}
						verify = func(proof, vk any, publicWitness witness.Witness) error {
							return groth16.Verify(proof.(groth16.Proof), vk.(groth16.VerifyingKey), publicWitness)
						}
					case backend.PLONK:
						setup = func(ccs constraint.ConstraintSystem) (
							pk, vk any,
							pkBuilder, vkBuilder, proofBuilder func() any,
							err error) {
							srs, err := NewKZGSRS(ccs)
							if err != nil {
								return nil, nil, nil, nil, nil, err
							}
							pk, vk, err = plonk.Setup(ccs, srs)
							return pk, vk, func() any { return plonk.NewProvingKey(curve) }, func() any { return plonk.NewVerifyingKey(curve) }, func() any { return plonk.NewProof(curve) }, err
						}
						prove = func(ccs constraint.ConstraintSystem, pk any, fullWitness witness.Witness, opts ...backend.ProverOption) (proof any, err error) {
							return plonk.Prove(ccs, pk.(plonk.ProvingKey), fullWitness, opts...)
						}
						verify = func(proof, vk any, publicWitness witness.Witness) error {
							return plonk.Verify(proof.(plonk.Proof), vk.(plonk.VerifyingKey), publicWitness)
						}
					case backend.PLONKFRI:
						setup = func(ccs constraint.ConstraintSystem) (
							pk, vk any,
							pkBuilder, vkBuilder, proofBuilder func() any,
							err error) {
							pk, vk, err = plonkfri.Setup(ccs)
							return pk, vk, func() any { return nil }, func() any { return nil }, func() any { return nil }, err
						}
						prove = func(ccs constraint.ConstraintSystem, pk any, fullWitness witness.Witness, opts ...backend.ProverOption) (proof any, err error) {
							return plonkfri.Prove(ccs, pk.(plonkfri.ProvingKey), fullWitness, opts...)
						}
						verify = func(proof, vk any, publicWitness witness.Witness) error {
							return plonkfri.Verify(proof, vk.(plonkfri.VerifyingKey), publicWitness)
						}
					default:
						panic("backend not implemented")
					}

					// proof system setup.
					pk, vk, pkBuilder, vkBuilder, _, err := setup(ccs)
					assert.checkError(err, b, curve, nil, nil)

					// for each valid witness, run the prover and verifier
					for _, w := range validWitnesses {
						assert.Run(func(assert *Assert) {
							assert.t.Parallel()
							proof, err := prove(ccs, pk, w.full, opt.proverOpts...)
							assert.checkError(err, b, curve, w.full, lazySchema(circuit))

							err = verify(proof, vk, w.public)
							assert.checkError(err, b, curve, w.full, lazySchema(circuit))

							if opt.Solidity {
								// check that the proof can be verified by gnark-solidity-checker
								if _vk, ok := vk.(verifyingKey); ok {
									assert.Run(func(assert *Assert) {
										assert.t.Parallel()
										assert.solidityVerification(b, _vk, proof, w.public)
									}, "solidity", b.String(), curve.String())
								}
							}

							// check proof serialization
							// assert.roundTripCheck(proof, proofBuilder, "proof")
						}, "valid_proof", curve.String(), b.String())
					}

					// for each invalid witness, run the prover only, it should fail.
					for _, w := range invalidWitnesses {
						assert.Run(func(assert *Assert) {
							assert.t.Parallel()
							_, err := prove(ccs, pk, w.full, opt.proverOpts...)
							assert.mustError(err, b, curve, w.full, lazySchema(circuit))
						}, "invalid_proof", curve.String(), b.String())
					}

					// check serialization of proving and verifying keys
					if ccs.GetNbConstraints() <= SerializationThreshold && (curve == ecc.BN254 || curve == ecc.BLS12_381) {
						assert.roundTripCheck(pk, pkBuilder, "proving_key")
						assert.roundTripCheck(vk, vkBuilder, "verifying_key")
					}

				}, curve.String(), b.String())
			}
		}

	})

	// TODO @gbotrel re-activate this.
	if false && opt.Fuzzing {
		// TODO may not be the right place, but ensures all our tests call these minimal tests
		// (like filling a witness with zeroes, or binary values, ...)
		assert.Run(func(assert *Assert) {
			assert.Fuzz(circuit, 5, opts...)
		}, "fuzz")
	}
}
