package solidity

import (
	"bytes"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/examples/cubic"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/suite"
)

type ExportSolidityTestSuite struct {
	suite.Suite

	// backend
	backend *backends.SimulatedBackend

	// verifier contract
	verifierContract *Verifier

	// groth16 gnark objects
	vk      groth16.VerifyingKey
	pk      groth16.ProvingKey
	circuit cubic.Circuit
	r1cs    r1cs.R1CS
}

func TestRunExportSolidityTestSuite(t *testing.T) {
	suite.Run(t, new(ExportSolidityTestSuite))
}

func (t *ExportSolidityTestSuite) SetupTest() {
	const gasLimit uint64 = 8000029
	// setup simulated backend
	key, _ := crypto.GenerateKey()
	auth := bind.NewKeyedTransactor(key)
	genesis := map[common.Address]core.GenesisAccount{
		auth.From: {Balance: big.NewInt(10000000000)},
	}
	t.backend = backends.NewSimulatedBackend(genesis, gasLimit)

	// deploy verifier contract
	_, _, v, err := DeployVerifier(auth, t.backend)
	t.NoError(err, "deploy verifier contract failed")
	t.verifierContract = v
	t.backend.Commit()

	// read proving and verifying keys
	t.pk = groth16.NewProvingKey(gurvy.BN256)
	{
		f, _ := os.Open("cubic.pk")
		_, err = t.pk.ReadFrom(f)
		f.Close()
		t.NoError(err, "reading proving key failed")
	}
	t.vk = groth16.NewVerifyingKey(gurvy.BN256)
	{
		f, _ := os.Open("cubic.vk")
		_, err = t.vk.ReadFrom(f)
		f.Close()
		t.NoError(err, "reading verifying key failed")
	}

	t.r1cs, err = frontend.Compile(gurvy.BN256, &t.circuit)
	t.NoError(err, "compiling R1CS failed ")

}

func (t *ExportSolidityTestSuite) TestVerifyProof() {
	// create a valid proof
	var witness cubic.Circuit
	witness.X.Assign(3)
	witness.Y.Assign(35)
	proof, err := groth16.Prove(t.r1cs, t.pk, &witness)
	t.NoError(err, "proving failed")

	// ensure gnark (Go) code verifies it
	err = groth16.Verify(proof, t.vk, &witness)
	t.NoError(err, "verifying failed")

	// get proof bytes
	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	// solidity contract inputs
	var (
		a     [2]*big.Int
		b     [2][2]*big.Int
		c     [2]*big.Int
		input [1]*big.Int
	)

	// proof.Ar, proof.Bs, proof.Krs
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	// public witness
	input[0] = new(big.Int).SetUint64(35)

	// call the contract
	res, err := t.verifierContract.VerifyProof(nil, a, b, c, input)
	t.NoError(err, "calling verifier on chain gave error")
	t.True(res, "calling verifier on chain didn't succeed")

	// (wrong) public witness
	input[0] = new(big.Int).SetUint64(42)

	// call the contract should fail
	res, err = t.verifierContract.VerifyProof(nil, a, b, c, input)
	t.NoError(err, "calling verifier on chain gave error")
	t.False(res, "calling verifier on chain succeed, and shouldn't have")
}
