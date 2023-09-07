//go:build ci_full && !ci_light

package test

import "fmt"

const (
	lightProfile = false
	fullProfile  = true
)

func init() {
	fmt.Println("ci_full is set: running tests with DefaultProfile == FullProfile")
}
