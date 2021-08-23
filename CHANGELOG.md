
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