package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/consensys/gnark/backend/plonk"
	bn254plonk "github.com/consensys/gnark/backend/plonk/bn254"
	contract "github.com/consensys/gnark/backend/plonk/bn254/solidity/gopkg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
)

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func createSimulatedBackend(privateKey *ecdsa.PrivateKey) (*backends.SimulatedBackend, *bind.TransactOpts, error) {

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
	if err != nil {
		return nil, nil, err
	}

	balance := new(big.Int)
	balance.SetString("10000000000000000000", 10) // 10 eth in wei

	address := auth.From
	genesisAlloc := map[common.Address]core.GenesisAccount{
		address: {
			Balance: balance,
		},
	}

	// create simulated backend & deploy the contract
	blockGasLimit := uint64(4712388)
	client := backends.NewSimulatedBackend(genesisAlloc, blockGasLimit)

	return client, auth, nil

}

func getTransactionOpts(privateKey *ecdsa.PrivateKey, auth *bind.TransactOpts, client *backends.SimulatedBackend) (*bind.TransactOpts, error) {

	fromAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return nil, err
	}

	gasprice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, err
	}

	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)
	auth.GasLimit = uint64(500000)
	auth.GasPrice = gasprice

	return auth, nil

}

type cubicCircuit struct {
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

func (circuit *cubicCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

type commitmentCircuit struct {
	Public [3]frontend.Variable `gnark:",public"`
	X      [3]frontend.Variable
}

func (c *commitmentCircuit) Define(api frontend.API) error {

	committer, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("type %T doesn't impl the Committer interface", api)
	}
	commitment, err := committer.Commit(c.X[:]...)
	if err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		api.AssertIsDifferent(commitment, c.X[i])
		for _, p := range c.Public {
			api.AssertIsDifferent(p, 0)
		}
	}
	return err
}

func getVkProofCommitmentCircuit() (bn254plonk.Proof, bn254plonk.VerifyingKey, bn254.G2Affine) {

	var circuit commitmentCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	checkError(err)

	var witness commitmentCircuit
	witness.X = [3]frontend.Variable{3, 4, 5}
	witness.Public = [3]frontend.Variable{6, 7, 8}
	witnessFull, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	checkError(err)
	witnessPublic, err := witnessFull.Public()
	checkError(err)

	srs, err := test.NewKZGSRS(ccs)
	checkError(err)

	pk, vk, err := plonk.Setup(ccs, srs)
	checkError(err)

	proof, err := plonk.Prove(ccs, pk, witnessFull)
	checkError(err)

	err = plonk.Verify(proof, vk, witnessPublic)
	checkError(err)

	tvk := vk.(*bn254plonk.VerifyingKey)
	tproof := proof.(*bn254plonk.Proof)
	tsrs := srs.(*kzg.SRS)

	return *tproof, *tvk, tsrs.G2[1]
}

func getVkProofCubicCircuit() (bn254plonk.Proof, bn254plonk.VerifyingKey, bn254.G2Affine, []fr.Element) {

	var circuit cubicCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	checkError(err)

	var witness cubicCircuit
	witness.X = 3
	witness.Y = 35
	witnessFull, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	checkError(err)
	witnessPublic, err := witnessFull.Public()
	checkError(err)

	srs, err := test.NewKZGSRS(ccs)
	checkError(err)

	tsrs := srs.(*kzg.SRS)
	fmt.Printf("%s\n", tsrs.G2[1].String())

	pk, vk, err := plonk.Setup(ccs, srs)
	checkError(err)

	proof, err := plonk.Prove(ccs, pk, witnessFull)
	checkError(err)

	err = plonk.Verify(proof, vk, witnessPublic)
	checkError(err)

	tvk := vk.(*bn254plonk.VerifyingKey)
	tproof := proof.(*bn254plonk.Proof)
	twitness := witnessPublic.Vector().(fr.Vector)

	return *tproof, *tvk, tsrs.G2[1], twitness
}

func prettyPrintProof(proof bn254plonk.Proof) {

	for i := 0; i < 3; i++ {
		fmt.Printf("proof.wire_commitments[%d].X = %s;\n", i, proof.LRO[i].X.String())
		fmt.Printf("proof.wire_commitments[%d].Y = %s;\n", i, proof.LRO[i].Y.String())
	}
	fmt.Printf("proof.wire_commitments[3].X = %s;\n", proof.PI2.X.String())
	fmt.Printf("proof.wire_commitments[3].Y = %s;\n", proof.PI2.Y.String())

	fmt.Printf("proof.grand_product_commitment.X = %s;\n", proof.Z.X.String())
	fmt.Printf("proof.grand_product_commitment.Y = %s;\n", proof.Z.Y.String())

	for i := 0; i < 3; i++ {
		fmt.Printf("proof.quotient_poly_commitments[%d].X = %s;\n", i, proof.H[i].X.String())
		fmt.Printf("proof.quotient_poly_commitments[%d].Y = %s;\n", i, proof.H[i].Y.String())
	}

	for i := 0; i < 3; i++ {
		fmt.Printf("proof.wire_values_at_zeta[%d] = %s;\n", i, proof.BatchedProof.ClaimedValues[i+2].String())
	}

	fmt.Printf("proof.grand_product_at_zeta_omega = %s;\n", proof.ZShiftedOpening.ClaimedValue.String())
	fmt.Printf("proof.quotient_polynomial_at_zeta = %s;\n", proof.BatchedProof.ClaimedValues[0].String())
	fmt.Printf("proof.linearization_polynomial_at_zeta = %s;\n", proof.BatchedProof.ClaimedValues[1].String())
	fmt.Printf("proof.qcprime_at_zeta = %s;\n", proof.BatchedProof.ClaimedValues[7].String())
	fmt.Printf("proof.permutation_polynomials_at_zeta[0] = %s;\n", proof.BatchedProof.ClaimedValues[5].String())
	fmt.Printf("proof.permutation_polynomials_at_zeta[1] = %s;\n", proof.BatchedProof.ClaimedValues[6].String())

	fmt.Printf("proof.opening_at_zeta_proof.X = %s;\n", proof.BatchedProof.H.X.String())
	fmt.Printf("proof.opening_at_zeta_proof.Y = %s;\n", proof.BatchedProof.H.Y.String())

	fmt.Printf("proof.opening_at_zeta_omega_proof.X = %s;\n", proof.ZShiftedOpening.H.X.String())
	fmt.Printf("proof.opening_at_zeta_omega_proof.Y = %s;\n", proof.ZShiftedOpening.H.Y.String())

}

func prettyPrintVk(vk bn254plonk.VerifyingKey, g2 bn254.G2Affine) {

	// fft stuff
	fmt.Printf("vk.domain_size = %d;\n", vk.Size)
	fmt.Printf("vk.omega = %s;\n", vk.Generator.String())

	// // selectors
	fmt.Printf("vk.selector_commitments[0].X = %s;\n", vk.Ql.X.String())
	fmt.Printf("vk.selector_commitments[0].Y = %s;\n", vk.Ql.Y.String())

	fmt.Printf("vk.selector_commitments[1].X = %s;\n", vk.Qr.X.String())
	fmt.Printf("vk.selector_commitments[1].Y = %s;\n", vk.Qr.Y.String())

	fmt.Printf("vk.selector_commitments[2].X = %s;\n", vk.Qm.X.String())
	fmt.Printf("vk.selector_commitments[2].Y = %s;\n", vk.Qm.Y.String())

	fmt.Printf("vk.selector_commitments[3].X = %s;\n", vk.Qo.X.String())
	fmt.Printf("vk.selector_commitments[3].Y = %s;\n", vk.Qo.Y.String())

	fmt.Printf("vk.selector_commitments[4].X = %s;\n", vk.Qk.X.String())
	fmt.Printf("vk.selector_commitments[4].Y = %s;\n", vk.Qk.Y.String())

	fmt.Printf("vk.selector_commitments[5].X = %s;\n", vk.Qcp.X.String())
	fmt.Printf("vk.selector_commitments[5].Y = %s;\n", vk.Qcp.Y.String())

	// permutation commitments
	fmt.Printf("vk.permutation_commitments[0].X = %s;\n", vk.S[0].X.String())
	fmt.Printf("vk.permutation_commitments[0].Y = %s;\n", vk.S[0].Y.String())

	fmt.Printf("vk.permutation_commitments[1].X = %s;\n", vk.S[1].X.String())
	fmt.Printf("vk.permutation_commitments[1].Y = %s;\n", vk.S[1].Y.String())

	fmt.Printf("vk.permutation_commitments[2].X = %s;\n", vk.S[2].X.String())
	fmt.Printf("vk.permutation_commitments[2].Y = %s;\n", vk.S[2].Y.String())

	// k1, k2
	var k1, k2 fr.Element
	k1.Set(&vk.CosetShift)
	k2.Square(&vk.CosetShift)
	fmt.Printf("vk.permutation_non_residues[0] = %s;\n", k1.String())
	fmt.Printf("vk.permutation_non_residues[1] = %s;\n", k2.String())

	// g2
	fmt.Printf("vk.g2_x.X[0] = %s;\n", g2.X.A0.String())
	fmt.Printf("vk.g2_x.X[1] = %s;\n", g2.X.A1.String())
	fmt.Printf("vk.g2_x.Y[0] = %s;\n", g2.Y.A0.String())
	fmt.Printf("vk.g2_x.Y[1] = %s;\n", g2.Y.A1.String())

	// commitment index
	fmt.Printf("vk.commitmentIndex = %d;\n", vk.CommitmentInfo.CommitmentIndex)

}

func prettyPrintPublicInputs(pi []fr.Element) {
	for i := 0; i < len(pi); i++ {
		fmt.Printf("public_inputs[%d] = %s;\n", i, pi[i].String())
	}
}

type testCaseBase64 struct {
	kzgVk, plonkVk, proof string
	public                []*big.Int
}

var withCommitment = testCaseBase64{
	kzgVk:   "GY6Tk5INSDpyYL+3MftdJfGqSTM1qecSl+SFt67zEsIYAN7vEh8edkJqAGZeXER5Z0Mi1Pde2t1G3r1c2ZL27QkGidBYX/B17J6ZrWkMM5W8SzEzcLOO81Ws2tzRIpdbEshepduMbetKq3GAjctAj+PR52kMQ9N7TObMAWb6faoD22GNxX+zzw5NaxYIdjmiBoCe61jOCzumTa/0og0+exGcKRQ6Cn+maGnV9kNOayPbpqVuTKjg56amx2bUndcrJN7w0uf2P/eyd3Jm688Ga4RyPELlBQF03nGvtpo2k00cCEmQuNvxahB2cpq0Pj5RRkMsdN49gsCGSXyfB6hr5wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=",
	plonkVk: "AAAAAAAAAAgqV8SkhQtsJIFGPP+xUS1Rgy1rP2qCQn8bZbbhcgAAASszfeHIwU8i7JueL5av7zZSYnNm+BcKCpSNrUrBvV6AAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABd/6i9NA2Ku/waci+HhTZk/MwPxc6lSG/7/t0us1iwTg0JqNYGHcwtYxrd1WnZ2NZljLxSUpJU4QwGMBSRheIl+hE6xzblOPcY26scKvxnkTToc2B5b/iTHT5sXJWmXOLd3ixWf3uSzKwaW0bjfKH1Al28b1jjT5mnZfdzEN/i/ZioBSVOpfeEfRkUflCLzjDsGTkd/yCMwzrQmgbQg18wbTTUfx1P9qIOReKcez/qS6pwx3vWkai5tV2gfsEOF6xMqAUlTqX3hH0ZFH5Qi84w7Bk5Hf8gjMM60JoG0INfMGk01H8dT/aiDkXinHs/6kuqcMd71pGoubVdoH7BDhesTiC+CD9Qc55OF9DU09jfdpp/EtJ2kN2e2N7NdywP6yYQEAAAAAAAAAAQAAAAAAAAA=",
	proof:   "GlEPQxmraRIU29H/wK18ncuXvsOsPBqqIoTd3uc+Gaosk6KmCK5htfdhLSTTfxewyZw/tknKCq9CHP1WkrsWjwZKlxo4toVd5UIhz6OK8OfMmscd1GDkU3OQ4Gtm9ueUABDQJGfx7u48qgQGZtdg9DPJfQgkV3AdMD5t3yh0sQUR0/mCin9saaN3ZgyRykYPo+CIK75PiCs51UDayxaK/ixjsO8+CVFJoEmpDKPSl9UryJJo/+2pz4DVTuZLQmKvJ/49a3VqB5dEVt51aIbUPjc6a0CI0XLbbTxIcXPH+HMaQncOIyMtfTJi9N7pAB/tfYV8i094sbJ8TLsTYfZwEQ0vYtoOHbagRicslbM0a5rlGZXc27CvEbQzBEoGQn7WAOXkkVH1HbczBFo7ka214/joWKAQwbt35taouJLID3YVHLAGlqG3auw59u/YFIniTM4egM+Dum34wTGkZzqwDASrOs9WFOLtLNEoL45WZtwFyfuK37li/WQSVVFaxPHLCz1wabPq47Ouy4db1ecibVLnwM1dEzikzCKt57uB5PMZo4G107gRqhUY3lTpFCOE5jGTNz4bkN0Wg3O0Bwulwx4Yek3nrdSEZeykQ5HYGosYGGceCO6m73L72tzO/O2tGVUnUfwI2gv9hDqxQ19sMrmZD83gq3pqJgYkbX/i2aAAAAAIGsgojBmi8w4RGkhskqCbIqJer+/e4OLCIC5ecWZBVTANSKEI78fp5pcq/ceE189/ono9dzSH6Ti/gSafLJFhJwMKXyGfeTdovgTcED5l9/kjx6GJkMR62CksijVTwNz0CQpU+fvHM6lBvtm9fMtQhqQfrlv9SEFiNM6R9CqSqpktpGlNBCiAJI08lCPZPCoPAIcdOrLhM3CSpf5531t8WQHacqxuylAl+ZmiCs1JeRQtncP1/W/I6YpXL2xpdyP6G5vwIUvzGCdMGmKaSTSQZqWfyuR8ehoRmIB2lbon7OYD4C2NFDSjcwNkDighcVNkEjOGKcdK5vtrki449DsIZxmsV6jjuvnAvZ4U7gOLwypjPvPvYIGaoSSP1MbB4ovmDLsR3JNR5QpWY0F8X0DIUQsujGwAySOoCzJLK9ywunInuSkpykY5ulGqNDD/PCWPZg6D7SsTUl3LT/+Qi9lt6iJtr9SwGFJtrgjr7F3FZHjpoGuw8Vcro57pdcIJSEtjFXGN6eAaAOSnp+ZyALyazlcuYzD7vdBPGrpdmLY1kw8=",
	public:  []*big.Int{big.NewInt(1)},
}

func base64ToUint64Slice(s string) []uint64 {
	bytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	const size = 64 / 8
	if len(bytes)%size != 0 {
		panic("bad length")
	}
	res := make([]uint64, len(bytes)/size)
	for i := range res {
		binary.LittleEndian.Uint64(bytes[i*size : (i+1)*size])
	}
	return res
}

func base64ToUint256Slice(s string) []*big.Int {
	bytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	const size = 256 / 8
	if len(bytes)%size != 0 {
		panic("bad length")
	}
	res := make([]*big.Int, len(bytes)/size)
	for i := range res {
		res[i] = &big.Int{}
		res[i].SetBytes(bytes[i*size : (i+1)*size])
	}
	return res
}

func main() {

	// create account
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// create simulated backend
	client, auth, err := createSimulatedBackend(privateKey)
	checkError(err)

	// deploy the contract
	contractAddress, _, instance, err := contract.DeployContract(auth, client)
	checkError(err)
	client.Commit()

	// Interact with the contract
	auth, err = getTransactionOpts(privateKey, auth, client)
	checkError(err)

	// test hash
	// _, _, p, _ := bn254.Generators()
	// var bx, by big.Int
	// p.X.BigInt(&bx)
	// p.Y.BigInt(&by)
	// _, err = instance.TestHash(auth, &bx, &by, "BSB22-Plonk")
	// checkError(err)

	// test sum_i li*zi
	// d := fft.NewDomain(64)
	// var bz, bn, bw big.Int
	// d.Generator.BigInt(&bw)
	// fmt.Printf("w = Fr(%s)\n", d.Generator.String())
	// bz.SetUint64(29)
	// bn.SetUint64(d.Cardinality)
	// // bi.SetUint64(10)
	// inputs := make([]*big.Int, 10)
	// fmt.Printf("[")
	// for i := 0; i < 10; i++ {
	// 	inputs[i] = big.NewInt(int64(i) + 3)
	// 	fmt.Printf("Fr(%s), ", inputs[i].String())
	// }
	// fmt.Println("]")

	// test circuit
	// proof, vk, _, _ := getVkProofCubicCircuit()

	// wproof, err := os.Create("proof")
	// checkError(err)
	// proof.WriteRawTo(wproof)
	// wvk, err := os.Create("vk")
	// checkError(err)
	// vk.WriteTo(wvk)
	// wproof.Close()
	// wvk.Close()

	/*
			var proof bn254plonk.Proof
			var vk bn254plonk.VerifyingKey

			rproof, err := os.Open("proof")
			checkError(err)
			_, err = proof.ReadFrom(rproof)
			checkError(err)


				auth, err = getTransactionOpts(privateKey, auth, client)
				checkError(err)
				_, err = instance.TestBatchInvert(auth, inputs)
				checkError(err)

				auth, err = getTransactionOpts(privateKey, auth, client)
				checkError(err)
				_, err = instance.TestBatchComputeLagrange(auth, big.NewInt(12), &bz, &bw, &bn)
				checkError(err)


		rvk, err := os.Open("vk")
		checkError(err)
		_, err = vk.ReadFrom(rvk)
		checkError(err)

		rproof.Close()
		rvk.Close()

		vk.KZGSRS = new(kzg.SRS)
		vk.KZGSRS.G1 = make([]bn254.G1Affine, 1)
		_, _, vk.KZGSRS.G1[0], vk.KZGSRS.G2[0] = bn254.Generators()
		vk.KZGSRS.G2[1].X.A0.SetString("14227438095234809947593477115205615798437098135983661833593245518598873470133")
		vk.KZGSRS.G2[1].X.A1.SetString("10502847900728352820104995430384591572235862434148733107155956109347693984589")
		vk.KZGSRS.G2[1].Y.A0.SetString("7327864992410983220565967131396496522982024563883331581506589780450237498081")
		vk.KZGSRS.G2[1].Y.A1.SetString("21715068306295773599916956786074008492685752252069347482027975832766446299128")
	*/

	// prettyPrintProof(proof)
	// fmt.Println("")
	// prettyPrintVk(vk, vk.KZGSRS.G2[1])

	/*
		var witness cubicCircuit
		witness.X = 3
		witness.Y = 35
		witnessFull, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
		checkError(err)
		witnessPublic, err := witnessFull.Public()
		checkError(err)

		plonk.Verify(&proof, &vk, witnessPublic)
		checkError(err)
	*/

	// hFunc := sha256.New()
	// fs := fiatshamir.NewTranscript(hFunc, "gamma", "beta", "alpha", "zeta")
	// var buf [bn254.SizeOfG1AffineUncompressed]byte
	// var r fr.Element

	// for _, p := range vk.S {
	// 	buf = p.RawBytes()
	// 	err = fs.Bind("gamma", buf[:])
	// 	checkError(err)
	// }
	// buf = vk.Ql.RawBytes()
	// err = fs.Bind("gamma", buf[:])
	// checkError(err)

	// buf = vk.Qr.RawBytes()
	// err = fs.Bind("gamma", buf[:])
	// checkError(err)

	// fmt.Println(vk.Qm.String())

	// buf = vk.Qm.RawBytes()
	// err = fs.Bind("gamma", buf[:])
	// checkError(err)

	// buf = vk.Qo.RawBytes()
	// err = fs.Bind("gamma", buf[:])
	// checkError(err)

	// buf = vk.Qk.RawBytes()
	// err = fs.Bind("gamma", buf[:])
	// checkError(err)

	// var publicInput fr.Element
	// publicInput.SetUint64(35)
	// err = fs.Bind("gamma", publicInput.Marshal())
	// checkError(err)

	// buf = proof.PI2.RawBytes()
	// err = fs.Bind("gamma", buf[:])
	// checkError(err)

	// for _, p := range proof.LRO {
	// 	buf = p.RawBytes()
	// 	err = fs.Bind("gamma", buf[:])
	// 	checkError(err)
	// }

	// b, err := fs.ComputeChallenge("gamma")
	// checkError(err)
	// r.SetBytes(b)
	// fmt.Printf("gamma = %s\n", r.String())

	/*
		_, err = instance.TestPlonkVanilla(auth)
		checkError(err)
		client.Commit()
	*/

	_ = instance

	// query event
	query := ethereum.FilterQuery{
		FromBlock: big.NewInt(0),
		ToBlock:   big.NewInt(2),
		Addresses: []common.Address{
			contractAddress,
		},
	}

	logs, err := client.FilterLogs(context.Background(), query)
	checkError(err)

	contractABI, err := abi.JSON(strings.NewReader(contract.ContractMetaData.ABI))
	checkError(err)

	for _, vLog := range logs {

		// var event interface{}
		// err = contractABI.UnpackIntoInterface(&event, "PrintUint256", vLog.Data)
		// checkError(err)
		// solidityRes := event.(*big.Int)

		// // check against gnark-crypto
		// msg := p.Marshal()
		// dst := []byte("BSB22-Plonk")
		// count := 1
		// refRes, err := fr.Hash(msg, dst, count)
		// checkError(err)
		// var brefRes big.Int
		// refRes[0].BigInt(&brefRes)

		// if solidityRes.Cmp(&brefRes) != 0 {
		// 	fmt.Println("hashes do not match")
		// 	os.Exit(-1)
		// }

		var event interface{}
		err = contractABI.UnpackIntoInterface(&event, "PrintUint256", vLog.Data)
		checkError(err)
		fmt.Println(event)
	}
}
