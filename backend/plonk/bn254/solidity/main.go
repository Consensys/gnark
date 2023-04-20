package main

import (
	"context"
	"crypto/ecdsa"
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
	blockGasLimit := uint64(14712388)
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
	auth.GasLimit = uint64(800000)
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

	var proof bn254plonk.Proof
	var vk bn254plonk.VerifyingKey

	rproof, err := os.Open("proof.commit")
	checkError(err)
	_, err = proof.ReadFrom(rproof)
	checkError(err)

	rvk, err := os.Open("vk.commit")
	checkError(err)
	_, err = vk.ReadFrom(rvk)
	checkError(err)

	rproof.Close()
	rvk.Close()

	vk.KZGSRS = new(kzg.SRS)
	vk.KZGSRS.G1 = make([]bn254.G1Affine, 1)
	_, _, vk.KZGSRS.G1[0], vk.KZGSRS.G2[0] = bn254.Generators()
	vk.KZGSRS.G2[1].X.A0.SetString("3861286923073220011793349409046889289349533020715526625969101603056608090795")
	vk.KZGSRS.G2[1].X.A1.SetString("4777846902900565418590449384753263717909657903692016614099552076160357595620")
	vk.KZGSRS.G2[1].Y.A0.SetString("21022748302362729781528857183979865986597752242747307653138221198529458362155")
	vk.KZGSRS.G2[1].Y.A1.SetString("16406754891999554747479650379038048271643900448173543122927661446988296543616")

	vk.CommitmentInfo.CommitmentIndex = 3
	vk.CommitmentInfo.Committed = []int{1}

	var witness commitmentCircuit
	witness.X = [3]frontend.Variable{3, 4, 5}
	witness.Public = [3]frontend.Variable{6, 7, 8}
	witnessFull, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	checkError(err)
	witnessPublic, err := witnessFull.Public()
	checkError(err)

	err = plonk.Verify(&proof, &vk, witnessPublic)
	checkError(err)

	// Interact with the contract
	auth, err = getTransactionOpts(privateKey, auth, client)
	checkError(err)

	_, err = instance.TestPlonkVanilla(auth)
	checkError(err)
	client.Commit()

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

	contractABI, err := abi.JSON(strings.NewReader(string(contract.ContractABI)))
	checkError(err)

	for _, vLog := range logs {

		var event interface{}
		err = contractABI.UnpackIntoInterface(&event, "PrintBool", vLog.Data)
		checkError(err)
		fmt.Println(event)
	}
}
