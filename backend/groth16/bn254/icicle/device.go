package icicle

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark/logger"
	icicle_runtime "github.com/ingonyama-zk/icicle/v3/wrappers/golang/runtime"
)

var onceWarmUpDevice sync.Once

func warmUpDevice() {
	onceWarmUpDevice.Do(func() {
		log := logger.Logger()
		err := icicle_runtime.LoadBackendFromEnvOrDefault()
		if err != icicle_runtime.Success {
			panic(fmt.Sprintf("ICICLE backend loading error: %s", err.AsString()))
		}
		device := icicle_runtime.CreateDevice("CUDA", 0)
		log.Debug().Int32("id", device.Id).Str("type", device.GetDeviceType()).Msg("ICICLE device created")
		icicle_runtime.RunOnDevice(&device, func(args ...any) {
			err := icicle_runtime.WarmUpDevice()
			if err != icicle_runtime.Success {
				panic(fmt.Sprintf("ICICLE device warmup error: %s", err.AsString()))
			}
		})
	})
}
