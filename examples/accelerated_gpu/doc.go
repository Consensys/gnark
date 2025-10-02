// Package accelerated_gpu provides examples on how to use gnark with GPU acceleration.
//
// NB! This example requires a compatible GPU and acceleration library installed. See
// the [icicle] package documentation for details. The example can only be run
//
// To setup:
//
//	export CGO_LDFLAGS="-L/usr/local/lib -licicle_device -lstdc++ -lm -Wl,-rpath=/usr/local/lib"
//	export ICICLE_BACKEND_INSTALL_DIR="/usr/local/lib/backend/"
//
// To run:
//
//	go test -timeout 0m -tags debug,icicle -run ^TestExampleCircuit$ github.com/consensys/gnark/examples/accelerated_gpu -v -count=1
package accelerated_gpu
