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

// NbCpus nb cpus we play with
var nbCpus int

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

	// total number of tasks to queue up
	var nbTasks int

	//NbCpus := runtime.NumCPU()
	nbIterations := iEnd - iStart // not  +1 -> iEnd is not included
	nbIterationsPerCpus := nbIterations / nbCpus
	nbTasks = nbCpus

	// more CPUs than tasks: a CPU will work on exactly one iteration
	if nbIterationsPerCpus < 1 {
		nbIterationsPerCpus = 1
		nbTasks = nbIterations
	}

	var wg sync.WaitGroup

	for i := 0; i < nbTasks; i++ {
		wg.Add(1)
		_start := iStart + i*nbIterationsPerCpus
		_end := _start + nbIterationsPerCpus
		if i == nbTasks-1 {
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
	nbCpus = runtime.NumCPU()
	_ = getPool()
}

func getPool() *pool {
	initOnce.Do(func() {

		globalPool = &pool{
			chLow:  make(chan func(), 10*nbCpus), // TODO NbCpus only?
			chHigh: make(chan func(), 32*nbCpus),
			chJob:  make(chan struct{}, 10*32*(nbCpus)),
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
