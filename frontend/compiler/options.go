/*
Copyright © 2021 ConsenSys Software Inc.

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

package compiler

// CompileOption enables to set optional argument to call of frontend.Compile()
type CompileOption struct {
	capacity                  int
	ignoreUnconstrainedInputs bool
}

// WithOutput is a Compile option that specifies the estimated capacity needed for internal variables and constraints
func WithCapacity(capacity int) func(opt *CompileOption) error {
	return func(opt *CompileOption) error {
		opt.capacity = capacity
		return nil
	}
}

// IgnoreUnconstrainedInputs when set, the Compile function doesn't check for unconstrained inputs
func IgnoreUnconstrainedInputs(opt *CompileOption) error {
	opt.ignoreUnconstrainedInputs = true
	return nil
}
