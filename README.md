# `gnark` zk-SNARK library
[![License](https://img.shields.io/badge/license-Apache%202-blue)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/ConsenSys/gnark)](https://goreportcard.com/badge/github.com/ConsenSys/gnark)
[![PkgGoDev](https://pkg.go.dev/badge/mod/github.com/consensys/gnark)](https://pkg.go.dev/mod/github.com/consensys/gnark)
[![Documentation Status](https://readthedocs.com/projects/pegasys-gnark/badge/)][`gnark` User Documentation] [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.6093969.svg)](https://doi.org/10.5281/zenodo.6093969)

<img  width="100px"
src="logo_new.png">

`gnark` is a fast zk-SNARK library that offers a high-level API to design circuits. The library is open source and developed under the Apache 2.0 license


## Useful Links

* [`gnark` User Documentation]
* [`gnark` Playground]
* [`gnark` Issues]
* [`gnark` Benchmarks](https://docs.gnark.consensys.net/en/latest/#gnark-is-fast)


## `gnark` Users

To get started with `gnark` and write your first circuit, follow [these instructions][`gnark` User Documentation].

Checkout the [online playground][`gnark` Playground] to compile circuits and visualize constraint systems.


## Warning
**`gnark` has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. In particular, `gnark` makes no security guarantees such as constant time implementation or side-channel attack resistance.**

`gnark` and `gnark-crypto` packages are optimized for 64bits architectures (x86 `amd64`) and tested on Unix (Linux / macOS).


## Issues

`gnark` issues are tracked [in the GitHub issues tab][`gnark` Issues].

If you have any questions, queries or comments, [GitHub discussions] is the place to find us.

You can also get in touch directly: gnark@consensys.net


## Release Notes

[Release Notes](CHANGELOG.md)

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

### Example

Refer to the [`gnark` User Documentation]

Here is what `x**3 + x + 5 = y` looks like

```golang
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

// compiles our circuit into a R1CS
var circuit CubicCircuit
ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)

// groth16 zkSNARK: Setup
pk, vk, err := groth16.Setup(ccs)

// witness definition
assignment := CubicCircuit{X: 3, Y: 35}
witness, err := frontend.NewWitness(&assignment, ecc.BN254)
publicWitness, _ := witness.Public()

// groth16: Prove & Verify
proof, err := groth16.Prove(ccs, pk, witness)
err := groth16.Verify(proof, vk, publicWitness)
```


____

## Citing

If you use `gnark` in your research a citation would be appreciated.
Please use the following BibTeX to cite the most recent release.

```bib
@software{gnark-v0.6.4,
  author       = {Gautam Botrel and
                  Thomas Piellard and
                  Youssef El Housni and
                  Ivo Kubjas and
                  Arya Tabaie},
  title        = {ConsenSys/gnark: v0.6.4},
  month        = feb,
  year         = 2022,
  publisher    = {Zenodo},
  version      = {v0.6.4},
  doi          = {10.5281/zenodo.6093969},
  url          = {https://doi.org/10.5281/zenodo.6093969}
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
[`gnark` User Documentation]: https://docs.gnark.consensys.net/en/latest/
[GitHub discussions]: https://github.com/ConsenSys/gnark/discussions
[Proving schemes and curves]: https://docs.gnark.consensys.net/en/latest/Concepts/schemes_curves/
