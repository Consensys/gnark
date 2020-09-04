# Under the hood of a circuit

Technically, inside **gnark**, a circuit is implemented in a `ConstraintSystem`. 

A `ConstraintSystem` is (mostly) a collection of `Constraint`. In a circuit, those would be "gates": a box that takes "wires" in, and outputs a single "wire". As we will see, a `Constraint` is a more abstract and more general representation.

In **gnark**, when we design a circuit, we declare inputs (i.e `x := circuit.SECRET_INPUT("x")`) and use [gnark API]() to describe the circuit (i.e `a := circuit.Add(x, 3)`).

This phase fills the data structure of the `ConstraintSystem`. 

Some proving systems, like Groth16, use a particular type of constraint system called "rank 1 constraint system" (R1CS), which are constraints in the form `a * b == c`. 

## `ConstraintSystem` to `R1CS`

The `Constraint` struct used in the `ConstraintSystem` is different than the `r1c` (rank 1 constraint) used in the `R1CS`. 

One can see the `R1CS` as a "compiled" circuit --> the data structure is immutable and hence, simpler. It is also pointer-less, to avoid garbage collection overhead with large circuits. 

### What is a `Constraint`?

A `Constraint` is a list of `expression` that must be equal to an output `wire` (if they are not, we say the `Constraint` is not satisfied). 

An `expression` is an arithmetic statement (at most, operations are quadratic) `f(x0, x1, ..xn) = y`. 

For example, 
```golang
x := circuit.Add(y, z)
```

creates the expression `y * 1 + z * 1`:

```golang
expression := &linearExpression{
	term{Wire: y.outputWire, Coeff: curve.One()},
	term{Wire: z.outputWire, Coeff: curve.One()},
}
```

**Example:** `c = a xor b` has this form as a rank one constraint: `(2a)*b = a+b-c`, so `c = a+b-2ab`, the expression is then `a+b-2ab`.

An expression has to be converted into a rank one constraint. For the previours example, `a+b-2ab` along with `c` will be converted to `2ab = a+b-c`.


### The conversion

From the `ConstraintSystem` , we build a `R1CS` in 4 steps:
1. Loop through all the `Constraint` and collect the variables
2. Loop though all the `Constraint`, isolate the expressions involved in the computational graph, link the variable computed from the expression to the expression
3. Number the variables
4. Split the `Constraint` into `r1c`


### Solving the `R1CS`

Each expression provides one or several outputs once its inputs are instantiated. We can see then see them as a computational graph, each node being a constraint. 

If the user specifies all the inputs, all the variables can be instantiated. The only way to declare unconstrained variables is to declare an input. All other constraints are using these or resulting constraints for operations on this to be computed.

The constraints involved in the computational graph have been isolated in the previous step. We just have to post order them to know in what order we should loop through them.

**Example:**
```
    s := cs.New()

    x := s.SECRET_INPUT("x")

    v1 := s.Mul(x, x)
    v2 := s.Mul(v1, v1)
    s.Add(v1, v2)

    r1cs := cs.NewR1CS(&s)
```

The state of the r1cs is as follows (the numbering of the wires does not correspond to the variables v1 and v2):
```
variables:
wire_0, wire_1, wire_2, x, ONE_WIRE (=wire_4)

computational gaph:
0. (1*wire_2 )*(1*wire_2 )=1*wire_0
1. (1wire_2 +1*wire_0)*(1*wire_4) )=1*wire_1
2. (1*x )*(1*x)=1*wire_2

Graph ordering:
2, 0, 1
```

See that the constraints in the computational graph are not ordered (the order in which they are stored doesn't matter). After the post ordering, we see that the solver will use constraint 2 to compute the wire2 (corresponding to v1) from x, the user input, then the constraint 0, to compute wire0 (v2) from wire2, then the constraint 1 to get wire_1. The ONE_WIRE wire (wire_4) is a constant variable equal to 1, given to each circuit.