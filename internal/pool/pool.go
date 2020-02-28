/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pool

import (
	"runtime"
	"sync"
)

// Push schedules a function to be executed.
// if it's high priority and the job queue is full, executes synchronously the call
func Push(fn func(), highPriority bool) {
	getPool().push(fn, highPriority)
}

// Execute process in parallel the work function and wait for result
func Execute(iStart, iEnd int, work func(int, int), highPriority bool) {
	<-ExecuteAsync(iStart, iEnd, work, highPriority)
}

// ExecuteAsync process in parallel the work function and return a channel that notifies caller when
// work is done
func ExecuteAsync(iStart, iEnd int, work func(int, int), highPriority bool) chan bool {
	pool := getPool()

	interval := iEnd / runtime.NumCPU()
	if interval >= iEnd {
		interval = iEnd - 1
	}
	if interval < 1 {
		interval = 1
	}
	var wg sync.WaitGroup
	start := 0
	for start = iStart; start < iEnd; start += interval {
		wg.Add(1)
		_start := start
		_end := start + interval
		if _end > iEnd {
			_end = iEnd
		}
		pool.push(func() {
			work(_start, _end)
			wg.Done()
		}, highPriority)
	}
	chDone := make(chan bool, 1)
	go func() {
		wg.Wait()
		chDone <- true
	}()
	return chDone
}

var initOnce sync.Once
var globalPool *pool

type pool struct {
	chLow, chHigh chan func()
	chJob         chan struct{}
}

func worker(pool *pool) {
	for range pool.chJob {
		select {
		// if we have a high priority job, execute it.
		case job := <-pool.chHigh:
			job()
		default:
			// else, dequeue low priority task
			job := <-pool.chLow
			job()
		}

	}
}

func init() {
	_ = getPool()
}

func getPool() *pool {
	initOnce.Do(func() {
		nbCpus := runtime.NumCPU()
		globalPool = &pool{
			chLow:  make(chan func(), nbCpus*10), // TODO nbCpus only?
			chHigh: make(chan func(), nbCpus*10),
			chJob:  make(chan struct{}, 20*(nbCpus)),
		}

		for i := 0; i < nbCpus; i++ {
			go worker(globalPool)
		}
	})
	return globalPool
}

func (pool *pool) push(fn func(), highPriority bool) {
	if highPriority {
		select {
		case pool.chHigh <- fn:
		default:
			// channel is full, calling go routine is executing the function synchronously instead
			// this should be used only in the recursive FFT setting
			// because caller is already a worker from this pool
			fn()
			return
		}
	} else {
		pool.chLow <- fn
	}
	pool.chJob <- struct{}{}
}
