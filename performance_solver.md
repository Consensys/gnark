# Constraint Solver Performance Notes

## Target

Optimize the generated SparseR1CS solvers used by PLONK backends. The initial
reference workload is copied from `linea-monorepo/prover/gpu/plonk/plonk_test.go`'s
`BenchmarkPlonkECMul30`: 30 independent BN254 scalar-multiplication checks
compiled as a BLS12-377 PLONK SparseR1CS.

The one-off BLS12-377 changes were generalized through
`internal/generator/backend/template/representations/solver.go.tmpl` and
`system.go.tmpl`, then regenerated for all curve-specific constraint packages.

The main benchmark is:

```sh
GOWORK=off go test ./constraint/bls12-377 -run '^$' -bench '^BenchmarkPlonkECMul30Solve$' -benchtime=10x -count=3
```

`GOWORK=off` is needed in this local checkout because the parent `go.work` does
not include this module.

## Baseline

Baseline was measured before solver changes, after adding only the benchmark:

```text
BenchmarkPlonkECMul30Solve-18    5    483335808 ns/op
BenchmarkPlonkECMul30Solve-18    3    493032444 ns/op
```

Baseline used the default solver task count (`runtime.NumCPU()`, benchmark
suffix `-18`) on Apple M5 Max.

## Experiments

| Change | Result |
| --- | ---: |
| Baseline solver | 483-493 ms/op |
| Replace per-wire atomic solved counter with final solved scan | 378 ms/op |
| Direct typed fast path for built-in SparseR1C add/mul/bool/generic gates | 371 ms/op |
| Reuse per-worker hint `big.Int` inputs/outputs instead of pool allocations | 300 ms/op |
| Fill L/R/O rows during sparse solving instead of a second decompression pass | 269 ms/op |
| Direct calldata interpreter for `BlueprintGenericHint` | 265 ms/op |
| Pass read-only modulus directly to hints | 259 ms/op |
| Scratch-backed `big.Word` conversion for hint inputs | 242 ms/op |
| Lower parallel chunk target from 50 to 25 constraints per CPU | 240 ms/op |
| Native BLS12-377 fast paths for log-derivative `countHint` and `batchDivBySubHint` | 143 ms/op |
| Batch inversion inside native `batchDivBySubHint` | 139 ms/op |
| Native `rangecheck.DecomposeHint` and `bits.nBits` paths | 134 ms/op |
| Retune parallel chunk target to 25 constraints per CPU for generated solvers | 134 ms/op |
| Skip ignored inputs for the default BSB22 commitment placeholder | 118 ms/op |

Thread count sensitivity after the 4x changes still favors the default 18 workers:

```text
tasks=2     221 ms/op
tasks=4     178 ms/op
tasks=8     156 ms/op
tasks=12    144 ms/op
tasks=18    135 ms/op
```

## Final Result

Final isolated benchmark after template generalization and code generation:

```text
BenchmarkPlonkECMul30Solve-18    50    119930740 ns/op    1024147867 B/op    880836 allocs/op
```

Using the first measured baseline (`483335808 ns/op`) and the final audit run
(`119930740 ns/op`), this is a 4.03x speedup.

## Generated Solver Benchmarks

The generated `BenchmarkSolve/scs` benchmark is a small arithmetic circuit with
no heavy hint traffic. It mainly checks that the generalized solver does not
regress normal sparse solving:

```sh
GOWORK=off go test ./constraint/bn254 ./constraint/bls12-381 ./constraint/bw6-761 ./constraint/grumpkin -run '^$' -bench 'BenchmarkSolve/scs$' -benchtime=3x -count=1
```

| Package | Before | After | Speedup |
| --- | ---: | ---: | ---: |
| `constraint/bn254` | 796083 ns/op | 646986 ns/op | 1.23x |
| `constraint/bls12-381` | 740042 ns/op | 725944 ns/op | 1.02x |
| `constraint/bw6-761` | 968236 ns/op | 979986 ns/op | 0.99x |
| `constraint/grumpkin` | no test files | no test files | n/a |

## EVM Precompile Benchmarks

The added `std/evmprecompiles` benchmark compiles once per circuit and curve,
then times only `SparseR1CS.Solve`:

```sh
GOWORK=off go test ./std/evmprecompiles -run '^$' -bench 'BenchmarkSolveEvmprecompiles' -benchtime=1x -count=1
```

| Circuit / curve | Before | After | Speedup |
| --- | ---: | ---: | ---: |
| `bn254_ecmul/bn254` | 27243917 ns/op | 10625208 ns/op | 2.56x |
| `bn254_ecmul/bls12_377` | 10309917 ns/op | 10714167 ns/op | 0.96x |
| `ecrecover/bn254` | 51427083 ns/op | 18528292 ns/op | 2.78x |
| `ecrecover/bls12_377` | 18072583 ns/op | 17132000 ns/op | 1.05x |
| `bls12381_g1_msm_2/bn254` | 177734333 ns/op | 36841959 ns/op | 4.82x |
| `bls12381_g1_msm_2/bls12_377` | 38587625 ns/op | 39090875 ns/op | 0.99x |

BLS12-377 precompile rows are mostly flat because the BLS12-377 solver already
had the manual optimization before this generalization pass. The BN254 rows show
the effect of moving the optimization into generated code.

## Preprocessing

No separate preprocessing phase was added. The changes are runtime solver
changes only:

- built-in sparse gates are interpreted directly from existing calldata,
- generic hints are interpreted directly from existing calldata,
- L/R/O vectors are populated during solving,
- temporary hint conversion buffers are per-worker scratch state,
- selected trusted hints use native field implementations when the registered
  function has not been overridden,
- the default testing-only BSB22 commitment placeholder skips conversion of
  ignored inputs; real prover overrides still use the supplied commitment hint.

There is therefore no preprocessing time to benchmark separately and no new
serialized asset to load in production.

## Verification

Commands run:

```text
GOWORK=off go generate ./internal/generator/backend
GOWORK=off go test ./constraint/solver ./frontend/cs/scs -count=1
GOWORK=off go test ./std/evmprecompiles -count=1
GOWORK=off go test ./backend/plonk/bn254 ./backend/plonk/bls12-377 ./backend/plonk/bls12-381 ./backend/plonk/bw6-761 -run 'Test.*Solve|Test.*Prove|Test.*Serialization|TestAPI' -count=1
GOWORK=off go test ./constraint/bn254 ./constraint/bls12-381 ./constraint/bw6-761 ./constraint/babybear ./constraint/koalabear ./constraint/tinyfield ./constraint/grumpkin -run '^TestSerialization/reference_small$|^TestSolve$|^Test$' -count=1
GOWORK=off go test ./constraint/bn254 ./constraint/bls12-381 ./constraint/bw6-761 ./constraint/grumpkin -run '^$' -bench 'BenchmarkSolve/scs$' -benchtime=3x -count=1
GOWORK=off go test ./std/evmprecompiles -run '^$' -bench 'BenchmarkSolveEvmprecompiles' -benchtime=1x -count=1
GOWORK=off go test ./constraint/bls12-377 -run '^$' -bench '^BenchmarkPlonkECMul30Solve$' -benchtime=50x -count=1 -benchmem
git diff --check
```

Full generated constraint-package tests for the big curves currently fail in
`TestSerialization/gkr_cube` on a GKR blueprint round-trip mismatch. The same
class of failure was present before this work on BLS12-377 and does not exercise
the solver paths above. The small-field constraint packages pass.
