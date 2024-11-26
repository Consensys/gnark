package icicle

import (
	"sync"

	icicle_runtime "github.com/ingonyama-zk/icicle/v3/wrappers/golang/runtime"
)

var onceWarmUpDevice sync.Once

func warmUpDevice() {
	onceWarmUpDevice.Do(func() {
		icicle_runtime.LoadBackendFromEnvOrDefault()
		device := icicle_runtime.CreateDevice("CUDA", 0)
		icicle_runtime.RunOnDevice(&device, func(args ...any) {
			icicle_runtime.WarmUpDevice()
		})
	})
}
