<a name="v0.5.2"></a>

## [v0.5.2] - 2021-11-03


### Breaking changes

- circuit `Define(... cs *frontend.ConstraintSystem)` now takes an interface `Define( ... api frontend.API)`
- assert helper is now under `backend/` (instead of `backend/groth16` and `backend/plonk`)

### Build
- updated to gnark-crypto v0.5.3

### Feat
- added `api.DivUnchecked` and `api.Div`. `DivUnchecked` will accept 0 / 0 == 0 as valid.
- `api.Sub` takes a variadic list of input (same as `api.Add`)
- plonk: kzg test srs is cached up to a certain size for faster tests
- removed hardcoded bit size in ToBinary, which now depends by default on `fr.Element` bit size
- api.ToBinary: constraint unsatisfied now has debugInfo
- unset variables: error message comes with a stack trace
- added bandersnatch circuit component under `std/`
- `frontend.Compile` now check that all secret and public inputs are constrained. Check can be ignore through compile option (`frontend.IgnoreUnconstrainedInputs`)
- added UnsafeReadFrom for groth16 Proving and Verifying keys, which doesn't perform subgroup checks on the decoded points

### Fix
- incorrect formula in api.Select when parameters are constant
- plonk: reduce duplicate constraint when splitting r1c in the frontend
- plonk: build permutation index out of bounds 

### Tests

- added a `test/` package with a test execution engine cross checking constraint system with `big.Int` arithmetic
- bases for `Fuzzing` witness and cross checking constraint system output with test execution engine

### Perf
- `api.AssertIsLessOrEqual`: reduced redundant constraints in range check
- std/groth16: ml with short addition chain (13245cs -> 12297, marginal gain)

### Refactor
- all circuits use frontend.API in place of *frontend.ConstraintSystem
- use ecc.Info() where possible to get modulus or field size


### Pull Requests
- Merge pull request [#159](https://github.com/consensys/gnark/issues/159) from ConsenSys/std/bandersnatch
- Merge pull request [#164](https://github.com/consensys/gnark/issues/164) from ConsenSys/perf-scs-compile
- Merge pull request [#161](https://github.com/consensys/gnark/issues/161) from ConsenSys/test-engine-with-hints
- Merge pull request [#162](https://github.com/consensys/gnark/issues/162) from ConsenSys/std/pairing
- Merge pull request [#160](https://github.com/consensys/gnark/issues/160) from ConsenSys/perf-unsafe-decoding
- Merge pull request [#156](https://github.com/consensys/gnark/issues/156) from ConsenSys/std/twistedEdwards
- Merge pull request [#151](https://github.com/consensys/gnark/issues/151) from ConsenSys/testable-circuits
- Merge pull request [#153](https://github.com/consensys/gnark/issues/153) from ConsenSys/fix/plonk_constraints_blowup
- Merge pull request [#146](https://github.com/consensys/gnark/issues/146) from ConsenSys/feat/ml-snark-pairing
- Merge pull request [#148](https://github.com/consensys/gnark/issues/148) from ConsenSys/perf-range-check

<a name="v0.5.1"></a>
## [v0.5.1] - 2021-09-20

### Build
- updated to gnark-crypto@v0.5.1

### Feat
- adds solver hints `cs.NewHint` [#139](https://github.com/ConsenSys/gnark/pull/139)
- adds `cs.AssertIsDifferent` [#131](https://github.com/ConsenSys/gnark/pull/131)
- consistent support of `cs.Println` and `debugInfo` [#142](https://github.com/ConsenSys/gnark/pull/142)
- adds sanity check in `frontend.Compile` to ensure constraint validity
- adds `witness.WriteSequence` to export expected witness sequence
- adds sanity checks in R1CS and SparseR1CS solvers
- adds ToHTML on SparseR1CS and R1CS
- add witness reconstruction methods. closes [#135](https://github.com/consensys/gnark/issues/135)

### Perf
- IsZero is now implemented with 3 constraints [#134](https://github.com/ConsenSys/gnark/pull/134)
- Groth16 maximize number of infinity points in G2 part of the ProvingKey [#130](https://github.com/ConsenSys/gnark/pull/130)

### Fix
- can constraint linear expressions to be boolean fixes [#136](https://github.com/consensys/gnark/issues/136)
- **eddsa:** addition of isOnCurve check
- **eddsa:** S not splitted (s<r) + 2,3 Double instead of [cofactor]G

### Refactor
- `groth16.Prove` and `plonk.Prove` takes `backend.ProverOption` as parameter
- factorized structs between `compiled.SparseR1CS` and `compiled.R1CS`
- assertions -> constraints in `R1CS` and `SparseR1CS`
- removed `r1c.SolvingMethod` in favor of `cs.NewHint`
- `cs.IsZero` doesn't need curveID anymore

### Test
- ensure `frontend.Compile` is deterministic
- added non regression for `cs.Println` and `debugInfo` traces
- added circuit statistic non regression tests
- added plonk path to `integration_test.go`
- added test from [#136](https://github.com/consensys/gnark/issues/136)


<a name="v0.5.0"></a>

## [v0.5.0] - 2021-08-20

### Build
- updated to latest gnark-crypto v0.5.0

### Feat
- add bls24-315 to gnark
- PlonK implementation as-in-the-paper
- removed `gnarkd` and `examples/benchmark`
- better errors for incorrect variable assignments [#120](https://github.com/consensys/gnark/issues/120)
- call stack displayed when AssertIsEqual fails
- remove term.CoeffValue and use constant coeff ID for special values instead
- added NbG1 and NbG2 apis on groth16 Proving and Verifying keys closes [#116](https://github.com/consensys/gnark/issues/116)
- addition of circuit component FiatShamir in std
- remove serialization test by default in assert helper
- addition of unit test for cyclo square in std/../e12.go
- LinearExpression implements Sort interface. replaced quickSort() by sort.Sort(...)
- SparseR1CS and PlonK objects implements io.ReaderFrom and io.WriterTo
- invalid gnark struct tag options return error at compile time fixes [#111](https://github.com/consensys/gnark/issues/111)

### Fix

- use of doubling formula instead of add(x,x) fixes [#114](https://github.com/consensys/gnark/issues/114)
- create cbor decoder with MaxArrayElements set to max value
- fix [#96](https://github.com/consensys/gnark/issues/96)
- r1cs compilation is deterministic, fixes [#90](https://github.com/consensys/gnark/issues/90)
- plonk circuit compiled with no constraints [#112](https://github.com/consensys/gnark/issues/112)
  
### Perf
- **frontend:** compile takes optional expected constraint number to reserve memory and speed up compile time
- **plonk:** prover uses available CPUs, memory allocation clean up
- **plonk:** frontend have fast path for -1, 0, 1 and 2 coefficients. less mem allocs.
- replaced string concat in frontend with strings.Builder
- **plonk:** when doing fft on domainH with coset, don't scale zero values
- **plonk:** minor tweaks, removing un-needed bitreverse and mem allocs
- **scs:** sparse r1cs have fast path for special coeffs operations
- **std:** adds E2/E12 square and cyclo square in E12 (used FinalExp)

### Refactor
- mimc uses Write(data) then Sum() instead of Sum(data)
- Hash-->Sum in mimc gadget
- **groth16:** SizePublicWitness to NbPublicWitness
- renamed GetCurveID() to CurveID() on groth16 objects

### Test
- test for Fiat Shamir gadget
- added reference frontend.Compile benchmarks



<a name="v0.4.0"></a>
## [v0.4.0]

### Docs
- added [`gnark` User Documentation]
- updated [Go package documentation](https://pkg.go.dev/mod/github.com/consensys/gnark)

### Feat
- **gnarkd:** exposing gnark APIs through RPCs ([#54](https://github.com/consensys/gnark/issues/54))
- **PlonK:** adding functionality to convert a constraint system to PlonK constraints ([#56](https://github.com/consensys/gnark/issues/56))
- **PlonK:** added experimental support for PlonK backend

### Fix
- inverse and div in frontend had some variable ID offset issues ([#62](https://github.com/consensys/gnark/issues/62))
- cs.Println doesn't trigger panic anymore
- Split S in EdDSA signature to prevent overflow [#88](https://github.com/consensys/gnark/issues/88)
- **fft:** fixed the ordering of cosets factor according to DIF/DIT

### Groth16
- VerifyingKey data structure change to ensure compatibility with other impl and Solidity in Ethereum. Serialization format change.

### Integration_test
- added witness serialization tests

### Refactor
- gurvy -> gnark-crypto
- moved fft in gnark-crypto
- bn256 -> bn254, bls377 -> bls12-377, etc. following gnark-crypto v0.4.0
- removed the Curve field in the R part of eddsa signature

### Test
- added frontend and backend fuzz.go, go-fuzz compatible format
- added cs.Println must not panic base test

### Build
- moved solidity integration tests in github.com/consensys/gnark-tests
- added integration fuzz test in backend/groth16/fuzz_test.go



[v0.4.0]: https://github.com/consensys/gnark/compare/v0.4.0...v0.4.0
[`gnark` User Documentation]: https://docs.gnark.consensys.net