//go:build !ci_full && ci_light

package test

import "fmt"

const (
	lightProfile = true
	fullProfile  = false
)

func init() {
	fmt.Println("ci_light is set: running tests with DefaultProfile == LightProfile")
}
