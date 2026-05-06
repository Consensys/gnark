# Description

Follow-up to #1751. PR #1751 made elliptic curve arithmetic complete by default, fixed the j=0 incompleteness in `sw_emulated.AddUnified`, and patched two soundness bugs in scalar-mul hint handling. While auditing whether those fixes were applied uniformly across `std/`, two further classes of soundness bug surfaced that PR #1751 did not touch:

## Bug 1: j=0 incompleteness in **four** other `AddUnified` implementations

The chord/tangent split + `areFinite` guard that PR #1751 applied to `sw_emulated.AddUnified` was missing in:

| File | Curve | Form |
|---|---|---|
| `std/algebra/native/sw_bls12377/g1.go::(*G1Affine).AddUnified` | BLS12-377 G1 | y² = x³ + 1, j=0, native Fp |
| `std/algebra/native/sw_bls12377/g2.go::(*g2AffP).AddUnified` | BLS12-377 G2 | D-twist, j=0, native Fp² |
| `std/algebra/native/sw_grumpkin/g1.go::(*G1Affine).AddUnified` | Grumpkin | y² = x³ − 17, j=0, native Fp |
| `std/algebra/emulated/sw_bls12381/g2.go::(*G2).AddUnified` | BLS12-381 G2 | D-twist, j=0, emulated Fp² |

**Exploit shape:** Brier–Joye `λ = (x₁² + x₁x₂ + x₂²) / (y₁ + y₂)` is not complete on j=0 curves. For a primitive cube root of unity `ω ∈ Fp` (which exists when `p ≡ 1 mod 3`, true for every BLS12 / BN base field and for Grumpkin's `Fp = BN254 Fr`), the pair `Q = -Φ(P) = (ω·P.x, -P.y)` satisfies `y_P + y_Q = 0` while `P ≠ -Q`. The old `selector3 = IsZero(p.Y + q.Y)` then triggers and returns the EVM-infinity convention `(0, 0)` — wrong answer for a finite curve sum. A malicious prover landing `Acc = -Φ(tableQ[0])` at `scalarMulGLV`'s boundary corrections could prove `[s]Q = O` for non-zero `[s]Q`. Concrete witness verified for BLS12-377 G1: with `P = G` and `Q = -Φ(P)`, the correct sum is `(29936237144…, 88641585806…)` but the buggy code returned `(0, 0)`.

**Fix (mirrors PR #1751 for `sw_emulated`):**
1. Replace Brier–Joye with the chord/tangent split:
   - chord: `λ = (q.Y − p.Y) / (q.X − p.X)` when `p.X ≠ q.X`
   - tangent: `λ = 3·p.X² / (2·p.Y)` when `p.X = q.X`
2. **Single-Div fold** (the optimization): build `num` and `den` with `Select` *before* dividing, so only one `Div` is performed (vs the two-`Div` form the chord/tangent pattern would otherwise need).
3. Gate the inverse-case override with `areFinite` so it cannot wrongly fire when one input is the SW infinity convention `(0, 0)`.

The same single-Div fold is also applied to `sw_emulated/point.go` for consistency, saving 1 `Div` + 1 `IsZero` on its existing two-`Div` chord/tangent code.

## Bug 2: trivial Eisenstein decomposition accepted in `scalarMulGLVAndFakeGLV`

PR #1751 added `AssertIsEqual(IsZero(s2), 0)` to `twistededwards.scalarMulFakeGLV` and `sw_emulated.scalarMulFakeGLV` to forbid the malicious all-zeros half-GCD decomposition that makes the lattice relation `s1 + s2·s = k·r` vacuous. The analogous defence was **missing** in the Eisenstein-decomposition variants:

- `std/algebra/emulated/sw_emulated/point.go::scalarMulGLVAndFakeGLV`
- `std/algebra/native/sw_bls12377/g1.go::scalarMulGLVAndFakeGLV`

Both call `halfGCDEisenstein` and check the relation `s·(v1 + λ·v2) + u1 + λ·u2 (− r·q) = 0`. A malicious hint returning `u1 = u2 = v1 = v2 (= q) = 0` makes the relation trivially `0 = 0`, and the in-circuit accumulator with all-zero bits collapses to the bias point that the final assertion already targets. **The hinted scalar-mul output `Q` is therefore unconstrained — a malicious prover can return any point as `[s]P`.**

I verified the exploit empirically by replacing the `halfGCDEisenstein` hint with one returning all-zeros: the circuit was satisfiable on master for both `sw_emulated` and `sw_bls12377 G1`, with arbitrary `Q`. This affects every consumer of the default scalar-mul path on endomorphism-bearing curves: ECDSA verification, ECRecover, recursive Groth16/Plonk verifiers using BN254 / BLS12-381 / BW6-761 / secp256k1 / native BLS12-377 G1.

**Fix:** assert that `(IsZero(v1) AND IsZero(v2)) == 0`, i.e., `v ≠ 0`. With `v ≠ 0` the relation forces `u` (and `q` natively) to a unique lattice point, which combined with the bit-length bounds and the in-circuit accumulator constraint pins `Q = [s]P`.

Fixes #(issue)

## Type of change

- [x] Bug fix (non-breaking change which fixes an issue)

# How has this been tested?

New regression tests covering both bug classes:

**Bug 1 (j=0 cube-root edge case):**
- [x] `std/algebra/native/sw_bls12377/g1_addunified_test.go` — 5 cases (`TestG1AddUnifiedCubeRootEdgeCase`, `…InfinityP`, `…Inverse`, `…Doubling`, `…Random`)
- [x] `std/algebra/native/sw_bls12377/g2_addunified_test.go` — 4 cases (`TestG2AddUnifiedCubeRootEdgeCase`, `…Random`, `…Doubling`, `…Inverse`)
- [x] `std/algebra/native/sw_grumpkin/g1_addunified_test.go` — 5 cases (mirror of BLS12-377 G1)
- [x] `std/algebra/emulated/sw_bls12381/g2_test.go` — added `case=cubeRoot` to `TestAddG2UnifiedTestSolveEdgeCases`

**Bug 2 (trivial Eisenstein decomposition):**
- [x] `std/algebra/native/sw_bls12377/g1_eisenstein_test.go::TestScalarMulGLVAndFakeGLV_TrivialDecompositionRegression` — replaces `halfGCDEisenstein` with all-zeros hint via `test.WithReplacementHint`, asserts the circuit becomes unsatisfiable.
- [x] `std/algebra/emulated/sw_emulated/point_test.go::TestScalarMulGLVAndFakeGLV_TrivialDecompositionRegression` — same shape for sw_emulated, exercising secp256k1.

I verified all new regression tests **fail on master** before the corresponding fix (each one catches its target bug). For BLS12-377 G1 j=0, the failure mode on master is `[assertIsEqual] 0 == 29936237144…` (buggy code returns X=0 where the correct sum has X=29936237144…). For both Eisenstein regressions on master, the malicious all-zeros hint is silently accepted with the message "trivial all-zeros Eisenstein decomposition was accepted — soundness break".

To reproduce:
```bash
go test -short ./std/algebra/native/sw_bls12377/...
go test -short ./std/algebra/native/sw_grumpkin/...
go test -short ./std/algebra/emulated/sw_bls12381/...
go test -short ./std/algebra/emulated/sw_emulated/...
```

Full downstream regression suite still green:
```bash
go test -short ./std/algebra/... ./std/signature/ecdsa/... ./std/evmprecompiles/... \
              ./std/commitments/kzg/... ./std/recursion/... ./internal/stats/...
```

# How has this been benchmarked?

Snippet stats regenerated via `internal/stats/generate -s`. Net deltas vs master combine the savings from the single-Div fold on `sw_emulated.AddUnified` and the small overhead from the new `IsZero(v1)·IsZero(v2)=0` assertion in `scalarMulGLVAndFakeGLV`:

| Snippet (R1CS / SCS) | master | this PR | Δ |
|---|---:|---:|---:|
| `scalar_mul_G1_bn254` (j=0) | 127 268 / 421 865 | **115 934 / 381 171** | **−8.9% / −9.6%** |
| `scalar_mul_G1_bn254_incomplete` | 55 409 / 199 958 | 55 441 / 200 004 | +0.058% / +0.023% |
| `scalar_mul_secp256k1` (j=0) | 128 728 / 426 780 | **117 264 / 385 623** | **−8.9% / −9.6%** |
| `scalar_mul_secp256k1_incomplete` | 56 093 / 202 472 | 56 125 / 202 518 | +0.057% / +0.023% |
| `scalar_mul_P256` (a=−3) | 96 724 / 328 895 | unchanged | 0 |
| `pairing_*` (all) | unchanged | unchanged | 0 |

The fold-trick saves ~9% on j=0 emulated scalar muls; the Eisenstein soundness assertion costs ~32 R1CS / ~46 SCS per scalar mul (1 `IsZero(v1)`, 1 `IsZero(v2)`, 1 `Mul`, 1 `AssertIsEqual` on emulated `Element[S]`). Net effect: ~9% saving on full j=0 scalar muls.

Standalone native AddUnified cost (one-shot snippet, used to validate the soundness-fix overhead, not committed):

| `addUnified_bls12_377_g1` (R1CS / SCS) | Before | After |
|---|---:|---:|
| `bw6_761` / `groth16` | 25 / 25 | 37 / 34 |
| `bw6_761` / `plonk` | 43 / 43 | 63 / 60 |

So +12 R1CS, +17–20 SCS per native AddUnified call. With ≤3 boundary unified-add calls per scalar mul, the j=0 soundness fix costs ~36 R1CS / ~50–60 SCS on a full scalar mul (~1500 R1CS / 3700 SCS), under 3%.

- [x] Benchmark via `internal/stats/generate`, on Macbook Pro M1, 32GB RAM

# Checklist:

- [x] I have performed a self-review of my code
- [x] I have commented my code, particularly in hard-to-understand areas
- [x] I have made corresponding changes to the documentation
- [x] I have added tests that prove my fix is effective or that my feature works
- [x] I did not modify files generated from templates
- [x] `golangci-lint` does not output errors locally
- [x] New and existing unit tests pass locally with my changes
- [x] Any dependent changes have been merged and published in downstream modules
