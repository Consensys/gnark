// Package maptocurve implements increment-and-check map-to-curve gadgets for
// short Weierstrass curves y² = x³ + ax + b over emulated fields.
//
// Two methods are provided:
//   - [Mapper.XIncrement]: encodes X = M·256 + K, verifies the curve equation, and
//     ensures Y has a 2^S-th root (inverse-exclusion witness) for j=0 curves.
//     Only practical for low 2-adicity fields (S ≤ 4). For high 2-adicity
//     fields (e.g. BLS12-377 with S=46, Grumpkin with S=28) the witness search
//     becomes infeasible — use [Mapper.YIncrement] instead.
//   - [Mapper.YIncrement]: encodes Y = M·256 + K, verifies the curve equation.
//     Simpler (no inverse-exclusion witness), works for any 2-adicity, and is
//     the recommended method for j=0 curves.
package maptocurve
