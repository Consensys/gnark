// Package witness provides an example of witness export as vector.
//
// gnark abstracts away the creation of the witness vector from assignment, but
// in some cases it is useful to have it as a vector (for example, to compare
// values against known state). This example shows how to create a witness
// vector from assignment and access individual values in it.
package witness
