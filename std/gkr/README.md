# Generic Knowledge of Computation (GKR) API

This package implements the GKR protocol in gnark. It allows proving the correct execution of a circuit on multiple instances at once.

## Overview

GKR is a protocol that allows efficient proving and verification of computations. The GKR API in gnark allows defining a circuit once and then proving its correct execution on multiple inputs.

## Usage

### Basic Usage

```go
// Initialize GKR API
gkr := gkr.NewApi()

// Define inputs with values for all instances at once
x, err := gkr.Import(xValues)
if err != nil {
    return err
}
y, err := gkr.Import(yValues)
if err != nil {
    return err
}

// Define circuit operations
z := gkr.Add(x, y)

// Solve and export results
solution, err := gkr.Solve(api)
if err != nil {
    return err
}
Z := solution.Export(z)

// Use the outputs
for i := range Z {
    api.AssertIsEqual(Z[i], expected[i])
}

// Verify the GKR proof
return solution.Verify(hashName)
```

### Incremental Instance Addition

Starting from version X.Y.Z, the GKR API supports incremental addition of instances:

```go
// Initialize GKR API
gkr := gkr.NewApi()

// Define the first instance to establish the circuit structure
x1, err := gkr.Import([]frontend.Variable{firstX})
if err != nil {
    return err
}
x2, err := gkr.Import([]frontend.Variable{firstY})
if err != nil {
    return err
}

// Define circuit (e.g., a hash function)
z := gkr.Add(x1, x2)  // In real usage, this would be more complex

// Solve for the first instance
solution, err := gkr.Solve(api)
if err != nil {
    return err
}

// Get first instance result immediately
firstOutput := solution.Export(z)[0]

// Later, add a new instance and get results immediately
inputAssignments := map[constraint.GkrVariable]frontend.Variable{
    x1: newX,
    x2: newY,
}
outputVars := []constraint.GkrVariable{z}
outputs, err := gkr.NewInstance(inputAssignments, outputVars, api)
if err != nil {
    return err
}

// Use the output of the new instance
newOutput := outputs[z]
```

### Creating Variables Without Assignments

You can also create variables without providing assignments using `NewVariable`:

```go
// Define the circuit structure first
x1, err := gkr.NewVariable()
if err != nil {
    return err
}
x2, err := gkr.NewVariable()
if err != nil {
    return err
}

// Define operations
z := gkr.Mul(x1, x2)

// Later, add instances with values
inputs1 := map[constraint.GkrVariable]frontend.Variable{
    x1: value1X,
    x2: value1Y,
}
outputs1, err := gkr.NewInstance(inputs1, []constraint.GkrVariable{z}, api)
```

## Advanced Features

### Dependencies Between Instances

GKR also supports dependencies between instances:

```go
// Define dependency: input of instance 1 depends on output of instance 0
gkr.Series(input, output, 1, 0)
```

### Working with Specific Instances

You can work with specific instances using `ExportInstance`:

```go
// Get output for specific instance
secondInstanceOutput := solution.ExportInstance(z, 1)
```

## Notes

- The number of instances must be a power of 2
- All instances must have the same circuit structure
- Dependencies between instances must not create cycles 
