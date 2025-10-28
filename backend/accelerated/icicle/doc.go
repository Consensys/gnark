// Package icicle implements backends using ICICLE library.
//
// This backend depends on the MIT-licensed [ICICLE] library. We currently
// support Groth16 proving system on the following curves:
//   - BLS12-377
//   - BLS12-381
//   - BN254
//   - BW6-761
//
// # Setup
//
// Before using the GPU-acceleration for ICICLE backend, you must install the
// CUDA toolkit and have a compatible NVIDIA GPU. See [CUDA instructions] for
// more details. We have tested with CUDA 13 on Linux (Ubuntu 24.04), but other
// versions should work as well.
//
// To initialize the ICICLE backend, follow the instructions in the [ICICLE]
// repository. Namely, first you should install the ICICLE library:
//
//	git clone https://github.com/ingonyama-zk/icicle-gnark
//	cd icicle-gnark/wrappers/golang
//	sudo ./build.sh -curve=all
//
// After that, the libraries are installed in `/usr/local/lib` and backend in
// `/usr/local/lib/backend`.
//
// Now set the environment variables:
//
//	export CGO_LDFLAGS="-L/usr/local/lib -licicle_device -lstdc++ -lm -Wl,-rpath=/usr/local/lib"
//	export ICICLE_BACKEND_INSTALL_DIR="/usr/local/lib/backend/"
//
// # Usage
//
// To use the ICICLE backend in your code, you should use the `icicle_groth16`
// package and use it for proving:
//
//	import icicle_groth "github.com/consensys/gnark/backend/accelerated/icicle/groth16"
//	...
//	pk := icicle_groth.NewProvingKey(curve)
//	n, err = pk.ReadFrom(r)
//	...
//	proof, err := icicle_groth.Prove(ccs, pk, witness)
//
// Finally, to build the application, use the `icicle` build tag to ensure the ICICLE integration is built:
//
//	go build -tags=icicle main.go
//
// # Proving key
//
// Keep in mind that the definitions of ICICLE and native gnark proving keys are
// different, so you cannot directly use the native gnark proving key with the
// ICICLE backend. However, the serialization is compatible, so you can use the
// `ReadFrom` and `WriteTo` methods to read/write the proving keys in binary
// format and use the same proving key for both backends.
//
// # Non-free backends
//
// gnark by default depends on the MIT-licensed ICICLE backend library. However, ICICLE
// can be used with non-free backends (newer CUDA and Metal), but this is not tested
// and we do not provide support for this.
//
// # Future compatibility
//
// Keep in mind that the accelerated backends are not automatically tested in
// the CI, so we cannot guarantee that future changes in gnark will not break
// the ICICLE integration. We also may change interfaces in the sub-packages to
// align with the external dependency changes.
//
// [ICICLE]: https://github.com/ingonyama-zk/icicle-gnark
// [CUDA instructions]: https://developer.nvidia.com/cuda-downloads?target_os=Linux
package icicle
