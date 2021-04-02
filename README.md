# gnark
[![License](https://img.shields.io/badge/license-Apache%202-blue)](LICENSE)  [![Go Report Card](https://goreportcard.com/badge/github.com/consensys/gnark)](https://goreportcard.com/badge/github.com/consensys/gnark) [![PkgGoDev](https://pkg.go.dev/badge/mod/github.com/consensys/gnark)](https://pkg.go.dev/mod/github.com/consensys/gnark)


`gnark` is a framework to execute (and verify) algorithms in zero-knowledge. It offers a high-level API to easily design circuits and fast implementation of state of the art ZKP schemes. 

`gnark` has not been audited and is provided as-is, use at your own risk. In particular, `gnark` makes no security guarantees such as constant time implementation or side-channel attack resistance.

`gnark` is optimized for `amd64` targets (x86 64bits) and tested on Unix (Linux / macOS).

Get in touch: zkteam@consensys.net

<img style="display: block;margin: auto;" width="80%"
src="banner_gnark.png">

### Proving systems

- [x] [Groth16](https://eprint.iacr.org/2016/260)

### Curves

- [x] BLS377
- [x] BLS381
- [x] BN254
- [x] BW761

## Getting started

### Prerequisites

You'll need to [install Go](https://golang.org/doc/install).

### Install `gnark` 

```bash
go get github.com/consensys/gnark
```

Note if that if you use go modules, in `go.mod` the module path is case sensitive (use `consensys` and not `ConsenSys`).

### Workflow

[Our blog post](https://hackmd.io/@zkteam/gnark) is a good place to start. In short:
1. Implement the algorithm using gnark API (written in Go)
2. `r1cs, err := frontend.Compile(&circuit)` to compile the circuit into a R1CS
3. `pk, vk := groth16.Setup(r1cs)` to generate proving and verifying keys
4. `groth16.Prove(...)` to generate a proof
5. `groth16.Verify(...)` to verify a proof


### Documentation

You can find the [documentation here](https://pkg.go.dev/mod/github.com/consensys/gnark). In particular:
* [frontend](https://pkg.go.dev/github.com/consensys/gnark/frontend) (writing a circuit)
* [groth16](https://pkg.go.dev/github.com/consensys/gnark/backend/groth16) (running groth16 workflow)


### Examples and `gnark` usage

Examples are located in `/examples`. 


#### /examples/cubic

1. To define a circuit, one must implement the `frontend.Circuit` interface:

```golang 
// Circuit must be implemented by user-defined circuits
type Circuit interface {
	// Define declares the circuit's Constraints
	Define(curveID ecc.ID, cs *ConstraintSystem) error
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
r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
```
Using struct tags attributes (similarly to `json` or `xml` encoders in Golang), `frontend.Compile()` will parse the circuit structure and allocate the user secret and public inputs [TODO add godoc link for details]. 

4. The circuit can be tested like so:

```golang
assert := groth16.NewAssert(t)

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
proof, err := groth16.Prove(r1cs, pk, witness)
err := groth16.Verify(proof, vk, publicWitness)
```



### API vs DSL

While several ZKP projects chose to develop their own language and compiler for the *frontend*, we designed a high-level API, in plain Go. 

Relying on Go ---a mature and widely used language--- and its toolchain, has several benefits.

Developpers can **debug**, **document**, **test** and **benchmark** their circuits as they would with any other Go program. Circuits can be versionned, unit tested and used into standard continious delivery workflows. IDE integration (we use VSCode) and all these features come for free and are stable accross platforms.

Moreover, `gnark` is not a black box and exposes APIs like a conventional cryptographic library (think `aes.encrypt([]byte)`). Complex solutions need this flexibility --- gRPC/REST APIs, serialization protocols, monitoring, logging, ... are all few lines of code away.

### Designing your circuit

#### Caveats

Three points to keep in mind when designing a circuit (which is close to constraint system programming):
1. Under the hood, there is only one variable type (field element). TODO
2. A `for` loop must have fix bounds. TODO
3. `if` statements (named `cs.Select()` like in `Prolog`). TODO.  


#### `gnark` standard library

Currently gnark provides the following components (see `gnark/std`):

* The Mimc hash function
* Merkle tree (binary, without domain separation)
* Twisted Edwards curve arithmetic (for bn256 and bls381)
* Signature (eddsa aglorithm, following https://tools.ietf.org/html/rfc8032)
* Groth16 verifier (1 layer recursive SNARK with BW761)

## Benchmarks

It is difficult to *fairly* and precisely compare benchmarks between libraries. Some implementations may excel in conditions where others may not (available CPUs, RAM or instruction set, WebAssembly target, ...). Nonetheless, it appears that `gnark`, is about **three time faster** than existing state-of-the-art.

Here are our measurements for the **Prover**. These benchmarks ran on a AWS c5a.24xlarge instance, with hyperthreading disabled.

The same circuit (computing 2^(2^x)) is benchmarked using `gnark`, `bellman` (bls381, ZCash), `bellman_ce` (bn256, matterlabs).  

### BN254

| nb constraints | 100000|32000000|64000000|
| -------- | --------| -------- | -------- |
| bellman_ce (s/op)|0.43|106|214.8|
| gnark (s/op)  |0.16|33.9|63.4|
| speedup  |x2.6|x3.1|x3.4|

On large circuits, that's **over 1M constraints per second**. 

### BLS381

| nb constraints | 100000|32000000|64000000|
| -------- | --------| -------- | -------- |
| bellman (s/op)|0.6|158|316.8|
| gnark (s/op)  |0.23|47.6|90.7|
| speedup  |x2.7|x3.3|x3.5|

## Resources requirements


Depending on the topology of your circuit(s), you'll need from 1 to 2GB of RAM per million constraint. 
Algorithms are very memory intensive, so hyperthreading won't help. Many physical cores will help, but at a point, throughput per core is decreasing.



____


## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our [code of conduct](CODE_OF_CONDUCT.md), and the process for submitting pull requests to us.


## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/consensys/gnark/tags). 


## License

This project is licensed under the Apache 2 License - see the [LICENSE](LICENSE) file for details
