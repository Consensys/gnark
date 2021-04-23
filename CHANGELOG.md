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