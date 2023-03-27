package common

import (
	"fmt"
	"os"
	"runtime/trace"
	"testing"

	"github.com/pkg/profile"
)

// ProfileTrace run the benchmark function with optionally, benchmarking and tracing
func ProfileTrace(b *testing.B, profiled, traced bool, fn func()) {
	var f *os.File
	var pprof interface{ Stop() }
	var err error

	if traced {
		f, err = os.Create(fmt.Sprintf("../profiling/%v-trace.out", b.Name()))
		if err != nil {
			panic(err)
		}

		err = trace.Start(f)
		if err != nil {
			panic(err)
		}

		defer trace.Stop()
	}

	if profiled {
		pprof = profile.Start(
			profile.ProfilePath(fmt.Sprintf("../profiling/%v-pprof", b.Name())),
			profile.Quiet,
		)
		defer pprof.Stop()
	}

	b.StartTimer()
	defer b.StopTimer()

	fn()
}
