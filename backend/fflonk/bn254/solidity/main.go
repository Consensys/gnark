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
	bn254_fflonk "github.com/consensys/gnark/backend/fflonk/bn254"
	contract "github.com/consensys/gnark/backend/fflonk/bn254/solidity/gopkg"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
)

// ∑ᵢ vⁱ [Pᵢ]
// Fᵣ
// ζ
// ω
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
	auth.GasLimit = uint64(309000)
	auth.GasPrice = gasprice

	return auth, nil

}

// ω
// H₁ + ζⁿ⁺²*H₂ + ζ²⁽ⁿ⁺²⁾*H₃
// @param x x coordinate of a point on Bn254(𝔽_p)
// @param y y coordinate of a point on Bn254(𝔽_p)
// ζⁿ-1
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

	// reading the proof, the pi, the verification key
	fvk, err := os.Open("./vk")
	checkError(err)
	var vk bn254_fflonk.VerifyingKey
	_, err = vk.ReadFrom(fvk)
	checkError(err)
	fvk.Close()

	fproof, err := os.Open("./proof")
	checkError(err)
	var proof bn254_fflonk.Proof
	_, err = proof.ReadFrom(fproof)
	checkError(err)
	err = fproof.Close()
	checkError(err)

	fpi, err := os.Open("./pi")
	checkError(err)
	nbPublicInputs := 1
	frBytes := 32
	bb := make([]byte, nbPublicInputs*frBytes)
	_, err = fpi.Read(bb)
	checkError(err)
	var pi []fr.Element
	for i := 0; i < len(bb); i += frBytes {
		var tmp fr.Element
		tmp.SetBytes(bb[i : i+frBytes])
		pi = append(pi, tmp)
	}
	err = fpi.Close()
	checkError(err)
	bpi := make([]*big.Int, len(pi))
	for i := 0; i < len(pi); i++ {
		bpi[i] = big.NewInt(0)
		pi[i].BigInt(bpi[i])
		// bpi[i].SetString("21888242871839275222246405745257275088548364400416034343698204186575808495619", 10)
	}

	err = bn254_fflonk.Verify(&proof, &vk, pi)
	checkError(err)

	// should output true: proof and public in puts are correct
	// res, err := instance.Verify(nil, proof.MarshalSolidity(), bpi)
	_, err = instance.Verify(auth, proof.MarshalSolidity(), bpi)
	checkError(err)
	client.Commit()
	// fmt.Printf("%t\n", res)
	// fmt.Printf("%d\n", res)

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
		err = contractABI.UnpackIntoInterface(&event, "PrintUint256", vLog.Data)
		checkError(err)
		fmt.Println(event)
	}
}
