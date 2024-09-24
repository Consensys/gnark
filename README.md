# `gnark` zk-SNARK library

[![Twitter URL](https://img.shields.io/twitter/url/https/twitter.com/gnark_team.svg?style=social&label=Follow%20%40gnark_team)](https://twitter.com/gnark_team) [![License](https://img.shields.io/badge/license-Apache%202-blue)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/ConsenSys/gnark)](https://goreportcard.com/badge/github.com/ConsenSys/gnark)
[![PkgGoDev](https://pkg.go.dev/badge/mod/github.com/consensys/gnark)](https://pkg.go.dev/mod/github.com/consensys/gnark)
[![Documentation Status](https://readthedocs.com/projects/pegasys-gnark/badge/)][`gnark` User Documentation] [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.5819104.svg)](https://doi.org/10.5281/zenodo.5819104)

`gnark` is a fast zk-SNARK library that offers a high-level API to design circuits. The library is open source and developed under the Apache 2.0 license.

`gnark` uses [`gnark-crypto`] for the finite-field arithmetic and out-circuit implementation of cryptographic algorithms.

`gnark` powers [`Linea zk-rollup`](https://linea.build). Include your project in the [known users](docs/KNOWN_USERS.md) section by opening a PR.

## Useful Links

* [`gnark` User Documentation]
* [`gnark` Playground]
* [`gnark` Issues]
* [`gnark` Benchmarks](https://docs.gnark.consensys.net/overview#gnark-is-fast) 🏁
* [`gnark-announce`] - Announcement list for new releases and security patches


## `gnark` Users

To get started with `gnark` and write your first circuit, follow [these instructions][`gnark` User Documentation].

Checkout the [online playground][`gnark` Playground] to compile circuits and visualize constraint systems.


## Security

**`gnark` and [`gnark-crypto`] have been [extensively audited](#audits), but are provided as-is, we make no guarantees or warranties to its safety and reliability. In particular, `gnark` makes no security guarantees such as constant time implementation or side-channel attack resistance.**

**To report a security bug, please refer to [`gnark` Security Policy](SECURITY.md).**

Refer to [known security advisories](https://github.com/Consensys/gnark/security/advisories?state=published) for a list of known security issues.

## Testing

`gnark` employs the following testing procedures:
* unit testing - we test the primitives in unit tests
* circuit testing - we test the circuit implementation against several targets:
  - test engine - instead of running the full prover and verifier stack, we run the computations only to ensure the completeness of the circuits
  - proof engines - we compile the circuits, run the setup, prove and verify using native implementation
  - Solidity verifier - in addition to the previous, we verify the proofs in Solidity verifier. See [`gnark-solidity-checker`]
* regression testing - we have implemented [tests for reported issues](internal/regression_tests) to avoid regressions
* constraint count testing - we have implemented [circuit size tests](internal/stats) to avoid regressions
* serialization testing - we check that [serialization round-trip is complete](io/roundtrip.go)
* side-effect testing - we check that circuit [compilation is deterministic](test/assert.go)
* fuzz testing:
  - circuit input fuzzing - we provide random inputs to the circuit to cause solver error
  - native input fuzzing - we provide random inputs to various native methods to cause errors. We have also stored initial fuzzing corpus for regression tests.
  - circuit definition fuzzing - we cooperate with Consensys Diligence to fuzz the circuit definitions to find bugs in the `gnark` circuit compiler.

The tests are automatically run during every PR and merge commit. We run full test suite only for the Linux on `amd64` target, but run short tests both for Windows target (`amd64`) and macOS target (`arm64`).

## Performance

`gnark` and `gnark-crypto` packages are optimized for 64bits architectures (x86 `amd64`) using assembly operations. We have generic implementation of the same arithmetic algorithms for ARM backends (`arm64`). We do not implement vector operations.

## Backwards compatibility

`gnark` tries to be backwards compatible when possible, however we do not guarantee that serialized object formats are static over different versions of `gnark`. Particularly - we do not have versioning implemented in the serialized formats, so using files between different versions of gnark may lead to undefined behaviour or even crash the program.

## Issues

`gnark` issues are tracked [in the GitHub issues tab][`gnark` Issues].

**To report a security bug, please refer to [`gnark` Security Policy](SECURITY.md).**

If you have any questions, queries or comments, [GitHub discussions] is the place to find us.

You can also get in touch directly: gnark@consensys.net

## Release Notes

[Release Notes](CHANGELOG.md)

## Audits

* [Kudelski Security - October 2022 - gnark-crypto (contracted by Algorand Foundation)](audits/2022-10%20-%20Kudelski%20-%20gnark-crypto.pdf)
* [Sigma Prime - May 2023 - gnark-crypto KZG (contracted by Ethereum Foundation)](audits/2024-05%20-%20Sigma%20Prime%20-%20kzg.pdf)
* [Consensys Diligence - June 2023 - gnark PLONK Solidity verifier](https://consensys.io/diligence/audits/2023/06/linea-plonk-verifier/)
* [LeastAuthority - August 2023 - gnark Groth16 Solidity verifier template (contracted by Worldcoin)](https://leastauthority.com/wp-content/uploads/2023/08/Worldcoin_Groth16_Verifier_in_EVM_Smart_Contract_Final_Audit_Report.pdf)
* [OpenZeppelin - November 2023 - gnark PLONK Solidity verifier template](https://blog.openzeppelin.com/linea-verifier-audit-1)
* [ZKSecurity.xyz - May 2024 - gnark standard library](audits/2024-05%20-%20zksecurity%20-%20gnark%20std.pdf)
* [OpenZeppelin - June 2024 - gnark PLONK prover and verifier](https://blog.openzeppelin.com/linea-prover-audit)
* [LeastAuthority - September 2024 - gnark general and GKR](audits/2024-09%20-%20Least%20Authority%20-%20arithm%20and%20GKR.pdf)

## Proving schemes and curves

Refer to [Proving schemes and curves] for more details.

`gnark` support the following zk-SNARKs:

- [x] [Groth16](https://eprint.iacr.org/2016/260)
- [x] [PlonK](https://eprint.iacr.org/2019/953)

which can be instantiated with the following curves

- [x] BN254
- [x] BLS12-381
- [x] BLS12-377
- [x] BW6-761
- [x] BLS24-315
- [x] BW6-633
- [x] BLS24-317

### Example

Refer to the [`gnark` User Documentation]

Here is what `x**3 + x + 5 = y` looks like

```golang
package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// CubicCircuit defines a simple circuit
// x**3 + x + 5 == y
type CubicCircuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *CubicCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func main() {
	// compiles our circuit into a R1CS
	var circuit CubicCircuit
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	// witness definition
	assignment := CubicCircuit{X: 3, Y: 35}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}

```

### GPU Support

#### Icicle Library

The following schemes and curves support experimental use of Ingonyama's Icicle GPU library for low level zk-SNARK primitives such as MSM, NTT, and polynomial operations:

- [x] [Groth16](https://eprint.iacr.org/2016/260)

instantiated with the following curve(s)

- [x] BN254

To use GPUs, add the `icicle` buildtag to your build/run commands, e.g. `go run -tags=icicle main.go`.

You can then toggle on or off icicle acceleration by providing the `WithIcicleAcceleration` backend ProverOption:

```go
    // toggle on
    proofIci, err := groth16.Prove(ccs, pk, secretWitness, backend.WithIcicleAcceleration())
    
    // toggle off
    proof, err := groth16.Prove(ccs, pk, secretWitness)
```

For more information about prerequisites see the [Icicle repo](https://github.com/ingonyama-zk/icicle).

## Citing

If you use `gnark` in your research a citation would be appreciated.
Please use the following BibTeX to cite the most recent release.

```bib
@software{gnark-v0.11.0,
  author       = {Gautam Botrel and
                  Thomas Piellard and
                  Youssef El Housni and
                  Ivo Kubjas and
                  Arya Tabaie},
  title        = {ConsenSys/gnark: v0.11.0},
  month        = sep,
  year         = 2024,
  publisher    = {Zenodo},
  version      = {v0.11.0},
  doi          = {10.5281/zenodo.5819104},
  url          = {https://doi.org/10.5281/zenodo.5819104}
}
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our [code of conduct](CODE_OF_CONDUCT.md), and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/consensys/gnark/tags).

## License

This project is licensed under the Apache 2 License - see the [LICENSE](LICENSE) file for details

[`gnark` Issues]: https://github.com/consensys/gnark/issues
[`gnark` Playground]: https://play.gnark.io
[`gnark` User Documentation]: https://docs.gnark.consensys.net/
[GitHub discussions]: https://github.com/ConsenSys/gnark/discussions
[Proving schemes and curves]: https://docs.gnark.consensys.net/Concepts/schemes_curves
[`gnark-announce`]: https://groups.google.com/g/gnark-announce
[@gnark_team]: https://twitter.com/gnark_team
[`gnark-crypto`]: https://github.com/Consensys/gnark-crypto
[`gnark-solidity-checker`]: https://github.com/Consensys/gnark-solidity-checker