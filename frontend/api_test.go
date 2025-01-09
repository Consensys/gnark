package api

import (
	"testing"
	"strings"

	"github.com/your-project/frontend"
	"github.com/stretchr/testify/require"
)

func TestPrintf(t *testing.T) {
	assert := require.New(t)
	
	var circuit struct {
		X, Y frontend.Variable
		Const frontend.Variable
	}
	
	api := NewTestAPI(t)
	
	// Create a mock to capture output
	var output strings.Builder
	api.SetOutput(&output)
	
	circuit.Const = 42
	api.Printf("const decimal: %d\n", circuit.Const)
	assert.Contains(output.String(), "const decimal: 42")
	
	// Test variables
	circuit.X = api.Add(10, 20)
	circuit.Y = api.Mul(5, 5)
	
	api.Printf("variables: %v %v\n", circuit.X, circuit.Y)
	
	// Test special formats
	api.Printf("coeff: %c var: %i\n", circuit.X, circuit.Y)
	
	// Test mixed output
	api.Printf("mixed: %d %x %v %c %i\n", 
		circuit.Const, circuit.X, circuit.Y, circuit.X, circuit.Y)
		
	// Test edge cases
	api.Printf("")
	api.Printf("%")
	api.Printf("%%")
	api.Printf("%d")
	api.Printf("%d%d", circuit.X)
}
