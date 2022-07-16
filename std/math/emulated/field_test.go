package emulated

// func newField(r *big.Int, nbBits int) (*field, error) {
// 	f, err := NewField(nil, r, nbBits)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return f.(*field), nil
// }

// func witnessData(q *big.Int) (X1, X2, X3, X4, X5, X6, Res *big.Int) {
// 	x1, _ := rand.Int(rand.Reader, q)
// 	x2, _ := rand.Int(rand.Reader, q)
// 	x3, _ := rand.Int(rand.Reader, q)
// 	x4, _ := rand.Int(rand.Reader, q)
// 	x5, _ := rand.Int(rand.Reader, q)
// 	x6, _ := rand.Int(rand.Reader, q)

// 	tmp := new(big.Int)
// 	res := new(big.Int)
// 	// res = x1^3
// 	tmp.Exp(x1, big.NewInt(3), q)
// 	res.Set(tmp)
// 	// res = x1^3 + 5*x2
// 	tmp.Mul(x2, big.NewInt(5))
// 	res.Add(res, tmp)
// 	// tmp = (x3-x4)
// 	tmp.Sub(x3, x4)
// 	tmp.Mod(tmp, q)
// 	// tmp2 = (x5+x6)
// 	tmp2 := new(big.Int)
// 	tmp2.Add(x5, x6)
// 	// tmp = (x3-x4)/(x5+x6)
// 	tmp2.ModInverse(tmp2, q)
// 	tmp.Mul(tmp, tmp2)
// 	tmp.Mod(tmp, q)
// 	// res = x1^3 + 5*x2 + (x3-x4)/(x5+x6)
// 	res.Add(res, tmp)
// 	res.Mod(res, q)
// 	return x1, x2, x3, x4, x5, x6, res
// }

// type EmulatedApiCircuit struct {
// 	f                      *field
// 	X1, X2, X3, X4, X5, X6 Element
// 	Res                    Element
// }

// func (c *EmulatedApiCircuit) init(f *field) {
// 	c.f = f
// 	c.X1 = newElement(f)
// 	c.X2 = newElement(f)
// 	c.X3 = newElement(f)
// 	c.X4 = newElement(f)
// 	c.X5 = newElement(f)
// 	c.X6 = newElement(f)
// 	c.Res = newElement(f)
// }

// func (c *EmulatedApiCircuit) Define(api frontend.API) error {
// 	f := c.f
// 	f.SetNativeAPI(api)

// 	// compute x1^3 + 5*x2 + (x3-x4) / (x5+x6)
// 	x13 := f.Mul(c.X1, c.X1, c.X1)
// 	fx2 := f.Mul(5, c.X2)
// 	nom := f.Sub(c.X3, c.X4)
// 	denom := f.Add(c.X5, c.X6)
// 	free := f.Div(nom, denom)
// 	res := f.Add(x13, fx2, free)
// 	f.AssertIsEqual(res, c.Res)
// 	return nil
// }

// func TestEmulatedApi(t *testing.T) {
// 	assert := test.NewAssert(t)

// 	f, err := newField(ecc.BN254.ScalarField(), 32)
// 	assert.NoError(err)

// 	var circuit EmulatedApiCircuit
// 	circuit.init(f)

// 	x1, x2, x3, x4, x5, x6, res := witnessData(ecc.BN254.ScalarField())
// 	witness := EmulatedApiCircuit{
// 		f:   f,
// 		X1:  f.ConstantFromBigOrPanic(x1),
// 		X2:  f.ConstantFromBigOrPanic(x2),
// 		X3:  f.ConstantFromBigOrPanic(x3),
// 		X4:  f.ConstantFromBigOrPanic(x4),
// 		X5:  f.ConstantFromBigOrPanic(x5),
// 		X6:  f.ConstantFromBigOrPanic(x6),
// 		Res: f.ConstantFromBigOrPanic(res),
// 	}

// 	assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization())
// }

// type WrapperCircuit struct {
// 	X1, X2, X3, X4, X5, X6 frontend.Variable
// 	Res                    frontend.Variable
// }

// func (c *WrapperCircuit) init(f *field) {
// 	c.X1 = newElement(f)
// 	c.X2 = newElement(f)
// 	c.X3 = newElement(f)
// 	c.X4 = newElement(f)
// 	c.X5 = newElement(f)
// 	c.X6 = newElement(f)
// 	c.Res = newElement(f)
// }

// func (c *WrapperCircuit) Define(api frontend.API) error {
// 	// compute x1^3 + 5*x2 + (x3-x4) / (x5+x6)
// 	x13 := api.Mul(c.X1, c.X1, c.X1)
// 	fx2 := api.Mul(5, c.X2)
// 	nom := api.Sub(c.X3, c.X4)
// 	denom := api.Add(c.X5, c.X6)
// 	free := api.Div(nom, denom)
// 	res := api.Add(x13, fx2, free)
// 	api.AssertIsEqual(res, c.Res)
// 	return nil
// }

// func TestTestEngineWrapper(t *testing.T) {
// 	assert := test.NewAssert(t)
// 	r := ecc.BN254.ScalarField()
// 	f, err := newField(r, 32)
// 	assert.NoError(err)

// 	var circuit WrapperCircuit
// 	circuit.init(f)

// 	x1, x2, x3, x4, x5, x6, res := witnessData(f.r)
// 	witness := WrapperCircuit{
// 		X1:  f.ConstantFromBigOrPanic(x1),
// 		X2:  f.ConstantFromBigOrPanic(x2),
// 		X3:  f.ConstantFromBigOrPanic(x3),
// 		X4:  f.ConstantFromBigOrPanic(x4),
// 		X5:  f.ConstantFromBigOrPanic(x5),
// 		X6:  f.ConstantFromBigOrPanic(x6),
// 		Res: f.ConstantFromBigOrPanic(res),
// 	}
// 	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
// 		f.SetNativeAPI(api)
// 		return f
// 	})
// 	err = test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
// 	assert.NoError(err)
// }

// func TestCompilerWrapper(t *testing.T) {
// 	assert := test.NewAssert(t)
// 	r := ecc.BN254.ScalarField()
// 	f, err := newField(r, 32)
// 	assert.NoError(err)

// 	var circuit WrapperCircuit
// 	circuit.init(f)
// 	x1, x2, x3, x4, x5, x6, res := witnessData(f.r)
// 	witness := WrapperCircuit{
// 		X1:  f.ConstantFromBigOrPanic(x1),
// 		X2:  f.ConstantFromBigOrPanic(x2),
// 		X3:  f.ConstantFromBigOrPanic(x3),
// 		X4:  f.ConstantFromBigOrPanic(x4),
// 		X5:  f.ConstantFromBigOrPanic(x5),
// 		X6:  f.ConstantFromBigOrPanic(x6),
// 		Res: f.ConstantFromBigOrPanic(res),
// 	}
// 	ccs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.WithBuilderWrapper(builderWrapper(f)))
// 	assert.NoError(err)
// 	t.Log(ccs.GetNbConstraints())
// 	// TODO: create proof
// 	_ = witness
// }

// func TestIntegrationApi(t *testing.T) {
// 	assert := test.NewAssert(t)
// 	r := ecc.BN254.ScalarField()
// 	f, err := newField(r, 32)
// 	assert.NoError(err)
// 	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
// 		f.SetNativeAPI(api)
// 		return f
// 	})
// 	keys := make([]string, 0, len(circuits.Circuits))
// 	for k := range circuits.Circuits {
// 		keys = append(keys, k)
// 	}
// 	sort.Strings(keys)

// 	for i := range keys {
// 		name := keys[i]
// 		tData := circuits.Circuits[name]
// 		assert.Run(func(assert *test.Assert) {
// 			_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, tData.Circuit, frontend.WithBuilderWrapper(builderWrapper(f)))
// 			assert.NoError(err)
// 		}, name, "compile")
// 		for i := range tData.ValidAssignments {
// 			assignment := tData.ValidAssignments[i]
// 			assert.Run(func(assert *test.Assert) {
// 				err = test.IsSolved(tData.Circuit, assignment, testCurve.ScalarField(), wrapperOpt)
// 				assert.NoError(err)
// 			}, name, fmt.Sprintf("valid=%d", i))
// 		}
// 		for i := range tData.InvalidAssignments {
// 			assignment := tData.InvalidAssignments[i]
// 			assert.Run(func(assert *test.Assert) {
// 				err = test.IsSolved(tData.Circuit, assignment, testCurve.ScalarField(), wrapperOpt)
// 				assert.Error(err)
// 			}, name, fmt.Sprintf("invalid=%d", i))
// 		}
// 	}
// }

// type pairingBLS377 struct {
// 	P          sw_bls12377.G1Affine `gnark:",public"`
// 	Q          sw_bls12377.G2Affine
// 	pairingRes bls12377.GT
// }

// //lint:ignore U1000 skipped test
// func (circuit *pairingBLS377) Define(api frontend.API) error {
// 	pairingRes, _ := sw_bls12377.Pair(api,
// 		[]sw_bls12377.G1Affine{circuit.P},
// 		[]sw_bls12377.G2Affine{circuit.Q})
// 	api.AssertIsEqual(pairingRes.C0.B0.A0, &circuit.pairingRes.C0.B0.A0)
// 	api.AssertIsEqual(pairingRes.C0.B0.A1, &circuit.pairingRes.C0.B0.A1)
// 	api.AssertIsEqual(pairingRes.C0.B1.A0, &circuit.pairingRes.C0.B1.A0)
// 	api.AssertIsEqual(pairingRes.C0.B1.A1, &circuit.pairingRes.C0.B1.A1)
// 	api.AssertIsEqual(pairingRes.C0.B2.A0, &circuit.pairingRes.C0.B2.A0)
// 	api.AssertIsEqual(pairingRes.C0.B2.A1, &circuit.pairingRes.C0.B2.A1)
// 	api.AssertIsEqual(pairingRes.C1.B0.A0, &circuit.pairingRes.C1.B0.A0)
// 	api.AssertIsEqual(pairingRes.C1.B0.A1, &circuit.pairingRes.C1.B0.A1)
// 	api.AssertIsEqual(pairingRes.C1.B1.A0, &circuit.pairingRes.C1.B1.A0)
// 	api.AssertIsEqual(pairingRes.C1.B1.A1, &circuit.pairingRes.C1.B1.A1)
// 	api.AssertIsEqual(pairingRes.C1.B2.A0, &circuit.pairingRes.C1.B2.A0)
// 	api.AssertIsEqual(pairingRes.C1.B2.A1, &circuit.pairingRes.C1.B2.A1)
// 	return nil
// }

// func TestPairingBLS377(t *testing.T) {
// 	t.Skip()
// 	assert := test.NewAssert(t)
// 	f, err := newField(ecc.BW6_761.ScalarField(), 32)
// 	assert.NoError(err)

// 	_, _, P, Q := bls12377.Generators()
// 	milRes, _ := bls12377.MillerLoop([]bls12377.G1Affine{P}, []bls12377.G2Affine{Q})
// 	pairingRes := bls12377.FinalExponentiation(&milRes)

// 	circuit := pairingBLS377{}

// 	pxb := new(big.Int)
// 	pyb := new(big.Int)
// 	qxab := new(big.Int)
// 	qxbb := new(big.Int)
// 	qyab := new(big.Int)
// 	qybb := new(big.Int)
// 	witness := pairingBLS377{
// 		pairingRes: pairingRes,
// 		P: sw_bls12377.G1Affine{
// 			X: f.ConstantFromBigOrPanic(P.X.ToBigIntRegular(pxb)),
// 			Y: f.ConstantFromBigOrPanic(P.Y.ToBigIntRegular(pyb)),
// 		},
// 		Q: sw_bls12377.G2Affine{
// 			X: fields_bls12377.E2{
// 				A0: f.ConstantFromBigOrPanic(Q.X.A0.ToBigIntRegular(qxab)),
// 				A1: f.ConstantFromBigOrPanic(Q.X.A1.ToBigIntRegular(qxbb)),
// 			},
// 			Y: fields_bls12377.E2{
// 				A0: f.ConstantFromBigOrPanic(Q.Y.A0.ToBigIntRegular(qyab)),
// 				A1: f.ConstantFromBigOrPanic(Q.Y.A1.ToBigIntRegular(qybb)),
// 			},
// 		},
// 	}

// 	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
// 		f.SetNativeAPI(api)
// 		return f
// 	})
// 	err = test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
// 	assert.NoError(err)
// 	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.WithBuilderWrapper(builderWrapper(f)))
// 	assert.NoError(err)
// 	// TODO: create proof
// }
