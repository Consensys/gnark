package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
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
	auth.GasLimit = uint64(300000)
	auth.GasPrice = gasprice

	return auth, nil

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

	d := fft.NewDomain(64)
	var bz, bi, bn, bw big.Int
	d.Generator.BigInt(&bw)
	fmt.Printf("w = Fr(%s)\n", d.Generator.String())
	bz.SetUint64(29)
	bn.SetUint64(d.Cardinality)
	bi.SetUint64(10)
	_, err = instance.TestEvalIthLagrange(auth, &bi, &bz, &bw, &bn)
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
		solidityRes := event.(*big.Int)
		fmt.Println(solidityRes.String())
	}

}
