## R1CS customized lazy inputs usage

### 1. finded out the duplicated structure

* f.g. in poseidon we have permutation many times.
* f.g. in mimc we have permutation many times.

### 2. create lazy definition(you have to care about key only) in constraint/lazy package, and register by below
```go=
    constraint.Register(key, createGeneralLazyInputsFunc(key))
```

### 3.record constraint for lazy, remember to match the key defined in above steps
```go=
    api.RecordConstraintsForLazy(cs.GetLazyPoseidonKey(len(state)), false, state...)
    // the repeatable constraints real code
    api.RecordConstraintsForLazy(cs.GetLazyPoseidonKey(len(state)), true, state...)
```

### 4.call lazify of ccs, to removed repeatable constraints