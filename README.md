# gnark
[![Gitter](https://badges.gitter.im/consensys-gnark/community.svg)](https://gitter.im/consensys-gnark/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge) [![License](https://img.shields.io/badge/license-Apache%202-blue)](LICENSE)  [![Go Report Card](https://goreportcard.com/badge/github.com/consensys/gnark)](https://goreportcard.com/badge/github.com/consensys/gnark) [![GoDoc](https://godoc.org/github.com/consensys/gnark?status.svg)](https://godoc.org/github.com/consensys/gnark)


`gnark` is a framework to execute (and verify) algorithms in zero-knowledge. It offers a high-level API to easily design circuits and fast implementation of state of the art ZKP schemes. 

`gnark` has not been audited and is provided as-is, use at your own risk. In particular, `gnark` makes no security guarantees such as constant time implementation or side-channel attack resistance.

<img style="display: block;margin: auto;" width="80%"
src="banner_gnark.png">

### Proving systems

- [x] [Groth16](https://eprint.iacr.org/2016/260)

### Curves

- [x] BLS377
- [x] BLS381
- [x] BN256
- [x] BW761

## Getting started

### Prerequisites

`gnark` is optimized for `amd64` targets (x86 64bits) and tested on Unix (Linux / macOS).
You'll need to [install Go](https://golang.org/doc/install).

### Install `gnark` 

#### Command line interface

```bash
go install github.com/ConsenSys/gnark
```

#### Library

Note that if you use `go.mod`, the module path is `github.com/consensys/gnark` (case sensitive). 

```bash
go get -u github.com/consensys/gnark
```

### Workflow

[Our blog post](https://hackmd.io/@zkteam/gnark) is a good place to start. In short:
1. Implement the algorithm using our API (written in Go)
2. Serialize the circuit in its R1CS form (`circuit.r1cs`) (in the `examples/cubic` subfolder, that would be `go run examples/cubic/main.go`)
3. Run `gnark setup circuit.r1cs` to generate proving and verifying keys
4. Run `gnark prove circuit.r1cs --pk circuit.pk --input input.json`to generate a proof
5. Run `gnark verify circuit.proof --vk circuit.vk --input input.json` to verify a proof

The input file has a the following JSON format:
```json
{
	"x":"3",
	"y":"0xdeff12"
}
```


Using the `gnark` CLI tool is **optional**. Developers may expose circuits through gRPC or REST APIs, export to Solidity, chose their serialization formats, etc. This is ongoing work on our side, but new feature suggestions or PR are welcome.

### Examples and `gnark` usage

Examples are located in `/examples`. 

Run `gnark --help` for a list of available commands. 

#### /examples/cubic

1. To define a circuit, one must implement the `frontend.Circuit` interface:

```golang 
// Circuit must be implemented by user-defined circuits
type Circuit interface {
	// Define declares the circuit's Constraints
	Define(curveID gurvy.ID, cs *ConstraintSystem) error
}
```

2. Here is what `x**3 + x + 5 = y` looks like

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
func (circuit *CubicCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	x3 := cs.Mul(circuit.X, circuit.X, circuit.X)
	cs.AssertIsEqual(circuit.Y, cs.Add(x3, circuit.X, 5))
	return nil
}

```

3. The circuit is then compiled (into a R1CS)

```golang
var circuit CubicCircuit

// compiles our circuit into a R1CS
r1cs, err := frontend.Compile(gurvy.BN256, &circuit)
```

Note that in most cases, the user don't need to *allocate* inputs (here X, Y) and it's done by the `frontend.Compile()` method using the struct tags attributes, similarly to `json` or `xml` encoders in Golang. 

4. The circuit can be tested like so:
```golang
{
	var witness CubicCircuit
	witness.X.Assign(42)
	witness.Y.Assign(42)

	assert.ProverFailed(r1cs, &witness)
}

{
	var witness CubicCircuit
	witness.X.Assign(3)
	witness.Y.Assign(35)
	assert.ProverSucceeded(r1cs, &witness)
}
```

5. The APIs to call Groth16 algorithms:
```golang
pk, vk := groth16.Setup(r1cs)
proof, err := groth16.Prove(r1cs, pk, solution)
err := groth16.Verify(proof, vk, solution)
```

6. Using the CLI
```
cd examples/cubic
go run cubic.go
gnark setup circuit.r1cs
gnark prove circuit.r1cs --pk circuit.pk --input input.json
gnark verify circuit.proof --vk circuit.vk --input input.json
```


### API vs DSL

While several ZKP projects chose to develop their own language and compiler for the *frontend*, we designed a high-level API, in plain Go. 

Relying on Go ---a mature and widely used language--- and its toolchain, has several benefits.

Developpers can **debug**, **document**, **test** and **benchmark** their circuits as they would with any other Go program. Circuits can be versionned, unit tested and used into standard continious delivery workflows. IDE integration (we use VSCode) and all these features come for free and are stable accross platforms.

Moreover, `gnark` is not a black box and exposes APIs like a conventional cryptographic library (think `aes.encrypt([]byte)`). Complex solutions need this flexibility --- gRPC/REST APIs, serialization protocols, monitoring, logging, ... are all few lines of code away.

### Designing your circuit

#### Caveats
TODO (field overflows, etc)

#### `gnark` standard library

Currently gnark provides the following components in its circuit library:

* The Mimc hash function
* Merkle tree (binary, without domain separation)
* Twisted Edwards curve arithmetic (for bn256 and bls381)
* Signature (eddsa aglorithm, following https://tools.ietf.org/html/rfc8032)
* Groth16 verifier (1 layer recursive SNARK with BW761)

## Benchmarks

It is difficult to *fairly* and precisely compare benchmarks between libraries. Some implementations may excel in conditions where others may not (available CPUs, RAM or instruction set, WebAssembly target, ...). Nonetheless, it appears that `gnark`, is **twice** faster than existing state-of-the-art.


Here are our measurements for the **Prover**, using BLS381 curve. These benchmarks ran on a AMD Ryzen 7 3700X (8 cores) with 32GB RAM. 


| nb constraints | 1000|40000|100000|1000000|10000000|
| -------- | --------| -------- | -------- |-------- |-------- |
| bellman (ms/op)|39|729|1537|12895|121468|
| gnark (ms/op)  |16|384|821|6372|65170|
| gain  |-59%|-47%|-47%|-51%|-46%|



____


## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our [code of conduct](CODE_OF_CONDUCT.md), and the process for submitting pull requests to us.
Get in touch: zkteam@consensys.net

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/consensys/gnark/tags). 


## License

This project is licensed under the Apache 2 License - see the [LICENSE](LICENSE) file for details
