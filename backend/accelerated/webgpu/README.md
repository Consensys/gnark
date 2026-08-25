# gnark WebGPU Backend

This package implements gnark prover using WSGL shaders for speeding up most heavy
cryptographic operations. For the prover coordination, we use Go implementation which
is compiled to WASM using Go toolchain. The Go implementation then calls the WSGL
shaders through a Typescrip bridge which in turn executes the WSGL shaders.

It supports Groth16 and PLONK proof systems over BN254, BLS12-377 and BLS12-381.

## Disclaimer

This is very experimental package. The APIs may change. The backend is not audited.

Currently G2 API tests are failing for BLS12-377 and BLS12-381, but the Groth16/PLONK
prover tests pass.

Due to using Go toolchain for compiling the proving coordinator to WASM, then the
assets are quite big. We have tried TinyGo, but it is incompatible with gnark-crypto
dependency as is.

## Overview

This directory contains gnark's browser WebGPU prover backend:

- `groth16/` contains the Go Groth16 accelerated backend and wasm entrypoints.
- `plonk/` contains the Go PLONK accelerated backend and wasm entrypoints.
- `internal/` contains shared Go bridge and wasm runtime helpers.
- `shaders/` contains the WGSL kernels used by the TypeScript runtime.
- `web/` contains the browser-facing TypeScript API and build configuration.

The Go packages are built only for `GOOS=js GOARCH=wasm`. They call the
TypeScript WebGPU runtime through `syscall/js`, and the TypeScript runtime
loads the Go wasm entrypoints from `web/dist/assets`.

## Build

Install TypeScript dependencies from `web/package-lock.json`:

```sh
cd backend/accelerated/webgpu/web
npm ci
```

Build the TypeScript package, bundled shaders, and Go wasm assets:

```sh
npm run build:all
```

Useful narrower targets:

```sh
npm run build
npm run build:shaders
npm run build:wasm
npm run build:wasm:groth16
npm run build:wasm:plonk
npm run lint
```

`npm run build:shaders` generates `web/src/curvegpu/shader_bundle.generated.ts` from `shaders/`.
