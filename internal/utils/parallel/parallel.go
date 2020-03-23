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

package parallel

import (
	"runtime"
	"sync"
)

// TODO clean this up. duplicate with gurvy
// groth16 should not need all this boiletplate

// Execute process in parallel the work function and wait for result
func Execute(iStart, iEnd int, work func(int, int), highPriority bool) {
	<-ExecuteAsync(iStart, iEnd, work, highPriority)
}
func ExecuteAsyncReverse(iStart, iEnd int, work func(int, int), highPriority bool) {
	// total number of tasks to queue up
	var nbTasks int

	//NbCpus := runtime.NumCPU()
	nbIterations := iEnd - iStart // not  +1 -> iEnd is not included
	nbIterationsPerCpus := nbIterations / runtime.NumCPU()
	nbTasks = runtime.NumCPU()

	// more CPUs than tasks: a CPU will work on exactly one iteration
	if nbIterationsPerCpus < 1 {
		nbIterationsPerCpus = 1
		nbTasks = nbIterations
	}

	extraTasks := iEnd - (iStart + nbTasks*nbIterationsPerCpus)
	extraTasksOffset := 0

	type tuple struct {
		a, b int
	}
	tasks := make([]tuple, nbTasks)
	for i := 0; i < nbTasks; i++ {
		_start := iStart + i*nbIterationsPerCpus + extraTasksOffset
		_end := _start + nbIterationsPerCpus
		if extraTasks > 0 {
			_end++
			extraTasks--
			extraTasksOffset++
		}
		tasks[i] = tuple{_start, _end}
	}
	for i := nbTasks - 1; i >= 0; i-- {
		_start := tasks[i].a
		_end := tasks[i].b
		go work(_start, _end)
	}
}

// ExecuteAsync process in parallel the work function and return a channel that notifies caller when
// work is done
func ExecuteAsync(iStart, iEnd int, work func(int, int), highPriority bool) chan bool {

	// total number of tasks to queue up
	var nbTasks int

	//NbCpus := runtime.NumCPU()
	nbIterations := iEnd - iStart // not  +1 -> iEnd is not included
	nbIterationsPerCpus := nbIterations / runtime.NumCPU()
	nbTasks = runtime.NumCPU()

	// more CPUs than tasks: a CPU will work on exactly one iteration
	if nbIterationsPerCpus < 1 {
		nbIterationsPerCpus = 1
		nbTasks = nbIterations
	}

	var wg sync.WaitGroup

	extraTasks := iEnd - (iStart + nbTasks*nbIterationsPerCpus)
	extraTasksOffset := 0

	for i := 0; i < nbTasks; i++ {
		wg.Add(1)
		_start := iStart + i*nbIterationsPerCpus + extraTasksOffset
		_end := _start + nbIterationsPerCpus
		if extraTasks > 0 {
			_end++
			extraTasks--
			extraTasksOffset++
		}
		go func() {
			work(_start, _end)
			wg.Done()
		}()
	}

	chDone := make(chan bool, 1)
	go func() {
		wg.Wait()
		chDone <- true
	}()
	return chDone
}
