package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254plonk "github.com/consensys/gnark/backend/plonk/bn254"
	contract "github.com/consensys/gnark/backend/plonk/bn254/solidity/gopkg"
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
	auth.GasLimit = uint64(1000000)
	auth.GasPrice = gasprice

	return auth, nil

}

func serialiseProof(proof bn254plonk.Proof) []byte {

	var res []byte

	// uint256 l_com_x;
	// uint256 l_com_y;
	// uint256 r_com_x;
	// uint256 r_com_y;
	// uint256 o_com_x;
	// uint256 o_com_y;
	var tmp64 [64]byte
	for i := 0; i < 3; i++ {
		tmp64 = proof.LRO[i].RawBytes()
		res = append(res, tmp64[:]...)
	}

	// uint256 h_0_x;
	// uint256 h_0_y;
	// uint256 h_1_x;
	// uint256 h_1_y;
	// uint256 h_2_x;
	// uint256 h_2_y;
	for i := 0; i < 3; i++ {
		tmp64 = proof.H[i].RawBytes()
		res = append(res, tmp64[:]...)
	}
	var tmp32 [32]byte

	// uint256 l_at_zeta;
	// uint256 r_at_zeta;
	// uint256 o_at_zeta;
	// uint256 s1_at_zeta;
	// uint256 s2_at_zeta;
	for i := 2; i < 7; i++ {
		tmp32 = proof.BatchedProof.ClaimedValues[i].Bytes()
		res = append(res, tmp32[:]...)
	}

	// uint256 grand_product_commitment_x;
	// uint256 grand_product_commitment_y;
	tmp64 = proof.Z.RawBytes()
	res = append(res, tmp64[:]...)

	// uint256 grand_product_at_zeta_omega;
	tmp32 = proof.ZShiftedOpening.ClaimedValue.Bytes()
	res = append(res, tmp32[:]...)

	// uint256 quotient_polynomial_at_zeta;
	// uint256 linearization_polynomial_at_zeta;
	tmp32 = proof.BatchedProof.ClaimedValues[0].Bytes()
	res = append(res, tmp32[:]...)
	tmp32 = proof.BatchedProof.ClaimedValues[1].Bytes()
	res = append(res, tmp32[:]...)

	// uint256 opening_at_zeta_proof_x;
	// uint256 opening_at_zeta_proof_y;
	tmp64 = proof.BatchedProof.H.RawBytes()
	res = append(res, tmp64[:]...)

	// uint256 opening_at_zeta_omega_proof_x;
	// uint256 opening_at_zeta_omega_proof_y;
	tmp64 = proof.ZShiftedOpening.H.RawBytes()
	res = append(res, tmp64[:]...)

	// uint256[] selector_commit_api_at_zeta;
	// uint256[] wire_committed_commitments;
	for i := 0; i < len(proof.Bsb22Commitments); i++ {
		tmp32 = proof.BatchedProof.ClaimedValues[7+i].Bytes()
		res = append(res, tmp32[:]...)
	}
	for i := 0; i < len(proof.Bsb22Commitments); i++ {
		tmp64 = proof.Bsb22Commitments[i].RawBytes()
		res = append(res, tmp64[:]...)
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

	// read proof, vk
	var proof bn254plonk.Proof
	fproof, err := os.Open("proof")
	checkError(err)
	proof.ReadFrom(fproof)
	fproof.Close()

	var vk bn254plonk.VerifyingKey
	fvk, err := os.Open("vk")
	checkError(err)
	vk.ReadFrom(fvk)
	fvk.Close()

	// publicInputs := make(fr.Vector, 3)
	// publicInputs[0].SetUint64(6)
	// publicInputs[1].SetUint64(7)
	// publicInputs[2].SetUint64(8)
	publicInputs := make(fr.Vector, 1)
	publicInputs[0].SetUint64(32)
	err = bn254plonk.Verify(&proof, &vk, publicInputs)
	checkError(err)

	bPublicInputs := make([]*big.Int, 1)
	for i := 0; i < 1; i++ {
		bPublicInputs[i] = big.NewInt(0)
		publicInputs[i].BigInt(bPublicInputs[i])
	}

	// Interact with the contract
	auth, err = getTransactionOpts(privateKey, auth, client)
	checkError(err)

	// sproof := serialiseProof(proof)
	// _, err = instance.TestVerifierGo(auth, sproof, bPublicInputs)
	_, err = instance.TestVerifier(auth)
	checkError(err)
	client.Commit()

	// _, err = instance.TestVerifier(auth)
	// checkError(err)
	// client.Commit()

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
		// err = contractABI.UnpackIntoInterface(&event, "PrintBool", vLog.Data)
		// err = contractABI.UnpackIntoInterface(&event, "PrintBytes32", vLog.Data)
		// err = contractABI.UnpackIntoInterface(&event, "PrintBytes", vLog.Data)
		checkError(err)
		fmt.Println(event)
	}
}
