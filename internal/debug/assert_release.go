// +build !debug

package debug

// Assert does nothing if debug flag is not provided
// if debug flag is provided, panics if condition is false.
func Assert(condition bool, message ...string) {
}
