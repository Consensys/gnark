package icicle

import (
	"fmt"
	"sync"

	icicle_runtime "github.com/ingonyama-zk/icicle/v3/wrappers/golang/runtime"
)

var onceWarmUpDevice sync.Once

func warmUpDevice() {
	onceWarmUpDevice.Do(func() {
		err := icicle_runtime.LoadBackendFromEnvOrDefault()
		if err != icicle_runtime.Success {
			panic(fmt.Sprintf("ICICLE backend loading error: %s", err.AsString()))
		}
		device := icicle_runtime.CreateDevice("CUDA", 0)
		icicle_runtime.RunOnDevice(&device, func(args ...any) {
			err := icicle_runtime.WarmUpDevice()
			if err != icicle_runtime.Success {
				panic(fmt.Sprintf("ICICLE device warmup error: %s", err.AsString()))
			}
		})
	})
}
