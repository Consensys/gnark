# Repository Guidelines

## Project Structure & Module Organization

`gnark` is a Go module (`go.mod`) centered on zk-SNARK circuit compilation and proving.

- `frontend/`: circuit definition APIs and builders.
- `backend/`: proving systems and backend integrations.
- `constraint/`: constraint-system representations and transforms.
- `std/`: reusable circuit gadgets and cryptographic primitives.
- `test/` and `*_test.go`: integration and package-level tests.
- `examples/`: runnable examples (also exercised in CI).
- `internal/`: non-public helpers (including regression and fuzz-related utilities).
- `docs/`, `audits/`: user docs and audit artifacts.

## Build, Test, and Development Commands

Use Go 1.24+ (CI runs on Go 1.23.x; module currently targets 1.24.9).

- `go test -short ./...`: fast baseline across packages.
- `go test -tags=release_checks,solccheck .`: root checks used in CI.
- `go test -tags=prover_checks ./test/... ./examples/...`: heavier prover paths.
- `go test -run=NONE -fuzz=FuzzIntcomp -fuzztime=30s ./internal/backend/ioutils`: fuzz target used in workflows.
- `go generate ./...`: required check; generated files must not introduce unexpected diffs.
- `goimports -w .` and `gofmt -w .`: formatting/import normalization.
- `golangci-lint run -v --timeout=5m`: static analysis (matches CI config).

## Coding Style & Naming Conventions

Follow idiomatic Go:

- Format with `goimports` first, then `gofmt` if needed.
- Use Go naming conventions: exported `CamelCase`, unexported `camelCase`.
- Keep package boundaries clear (`internal/` stays private).
- Name tests in `*_test.go`; prefer table-driven tests for circuit/API variants.

## Testing Guidelines

Every behavior change should include or update tests. Prioritize:

- unit tests near changed code,
- regression tests for bug fixes (see `internal/regression_tests`),
- circuit/prover coverage when modifying `backend/`, `frontend/`, or `std/`.

Run at least `go test -short ./...` locally before opening a PR.

## Commit & Pull Request Guidelines

Commit titles follow Conventional Commit style (enforced by `.gitlint`), e.g.:

- `feat: add Version() shortcut on proving key`
- `fix: correct raw key encoding path`

For PRs, include clear purpose, linked issues when relevant, and test evidence. CI enforces formatting, lint, generated-file cleanliness, and test suites. Formatting-only or trivial non-code changes are usually not accepted; batch them into substantive updates.

## Security & Reporting

Do not open public issues for vulnerabilities. Follow `SECURITY.md` for responsible disclosure.
