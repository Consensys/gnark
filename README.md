# gnark
[![License](https://img.shields.io/badge/license-Apache%202-blue)](LICENSE)  [![Go Report Card](https://goreportcard.com/badge/github.com/consensys/gnark)](https://goreportcard.com/badge/github.com/consensys/gnark) [![GoDoc](https://godoc.org/github.com/consensys/gnark?status.svg)](https://godoc.org/github.com/consensys/gnark)


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

## Getting started

### Prerequisites

`gnark` is optimized for Unix (Linux / macOS) 64bits platforms (and not tested on other architectures). 
You'll need to [install Go](https://golang.org/doc/install).

### Install `gnark`

```bash
git clone https://github.com/consensys/gnark.git
cd gnark
make
```

### Workflow

[Our blog post](https://hackmd.io/@zkteam/gnark) is a good place to start. In short:
1. Implement the algorithm using our API (written in Go)
2. Serialize the circuit in its R1CS form (`circuit.r1cs`) (in the `examples/cubic_equation` subfolder, that would be `go run -tags bls381 cubic.go`)
3. Run `gnark setup circuit.r1cs` to generate proving and verifying keys
4. Run `gnark prove circuit.r1cs --pk circuit.pk --input input`to generate a proof
5. Run `gnark verify circuit.proof --vk circuit.vk --input input.public` to verify a proof

Note that, currently, the input file has a simple csv-like format:
```csv
secret, x, 3
public, y, 35
```

Using the `gnark` CLI tool is **optional**. Developers may expose circuits through gRPC or REST APIs, export to Solidity, chose their serialization formats, etc. This is ongoing work on our side, but new feature suggestions or PR are welcome.

### Examples and `gnark` usage

Examples are located in `/examples`. 

Run `gnark --help` for a list of available commands. 

#### /examples/cubic_equation

```golang
// x**3 + x + 5  y
func main() {
	// create root constraint system
	circuit := cs.New()

	// declare secret and public inputs
	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	// specify constraints
	x3 := circuit.MUL(x, x, x)
	circuit.MUSTBE_EQ(y, circuit.ADD(x3, x, 5))

	circuit.Write("circuit.r1cs")
}
```

```
cd examples/cubic_equation
go run cubic.go
gnark setup circuit.r1cs
gnark prove circuit.r1cs --pk circuit.pk --input input
gnark verify circuit.proof --vk circuit.vk --input input.public
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

TODO

## Benchmarks

It is difficult to *fairly* and precisely compare benchmarks between libraries. Some implementations may excel in conditions where others may not (available CPUs, RAM or instruction set, WebAssembly target, ...). Nonetheless, it appears that `gnark`, is faster than existing state-of-the-art.

Here are our measurements for the **Prover**, using BLS381 curve. These benchmarks ran on a c5d.metal AWS instance (96 vCPUS, 192GB RAM):


| nb constraints | 1000|10000|40000|100000|1000000|10000000|
| -------- | --------|--------| -------- | -------- |-------- |-------- |
| bellman (ms/op)|103|183|450|807|5445|60045|
| gnark (ms/op)  |11|67|252|520|4674|56883|
| gain  |-89.3%|-63.4%|-44.0%|-35.6%|-14.2%|-5.3%|

On this configuration, for 1M constraints+, we're only using 30% of the CPUs! Work in progress to scale better--- with number of CPUs and number of constraints.

____
Here are some measurements on a consumer laptop (2016 MBP, 8cores, 16GB RAM):


| 40k constraints | Prove |Verify|
| -------- | --------|--------|
| bellman (ms/op)|2021|3.69|
| gnark (ms/op)  |1648|3.04|
| gain  |-18.5%|-17.6%|





## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our [code of conduct](CODE_OF_CONDUCT.md), and the process for submitting pull requests to us.
Get in touch: zkteam@consensys.net

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/consensys/gnark/tags). 


## License

This project is licensed under the Apache 2 License - see the [LICENSE](LICENSE) file for details
