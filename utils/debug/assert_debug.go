// +build debug

package debug

import "fmt"

func init() {
	fmt.Println("WARNING -- DEBUG FLAG IS ON")
}

// Assert does nothing if debug flag is not provided
// if debug flag is provided, panics if condition is false.
func Assert(condition bool, message ...string) {
	if !condition {
		if len(message) > 0 {
			panic(message[0])
		} else {
			panic("assertion failed")
		}
	}
}
