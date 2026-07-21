# gnark WebGPU Backend

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
