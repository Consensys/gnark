// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contract

import (
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// ContractABI is the input ABI used to generate the binding from.
const ContractABI = "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"a\",\"type\":\"uint256\"}],\"name\":\"PrintUint256\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"uint256[]\",\"name\":\"inputs\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"z\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"w\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"n\",\"type\":\"uint256\"}],\"name\":\"test_compute_sum_li_zi\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"res\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"i\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"z\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"w\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"n\",\"type\":\"uint256\"}],\"name\":\"test_eval_ith_lagrange\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"res\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"x\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"y\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"dst\",\"type\":\"string\"}],\"name\":\"test_hash\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"res\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

// ContractBin is the compiled bytecode used for deploying new contracts.
var ContractBin = "0x608060405234801561001057600080fd5b50611563806100206000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c8063437a9c6a14610046578063c7baa21714610076578063e0380a93146100a6575b600080fd5b610060600480360381019061005b9190610e31565b6100d6565b60405161006d9190610ec3565b60405180910390f35b610090600480360381019061008b9190610f93565b610125565b60405161009d9190610ec3565b60405180910390f35b6100c060048036038101906100bb9190611002565b610172565b6040516100cd9190610ec3565b60405180910390f35b60006100e4858585856101c1565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b816040516101159190610ec3565b60405180910390a1949350505050565b60006101328484846102dd565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b816040516101639190610ec3565b60405180910390a19392505050565b600061018085858585610443565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b816040516101b19190610ec3565b60405180910390a1949350505050565b6000806101ce858461051f565b90506000600190506000875190506000806000806101ec8b876105b8565b91506101f98760016105b8565b9050610205818361061f565b9250610211838a61061f565b9250610238838d60008151811061022b5761022a611069565b5b602002602001015161064a565b93506000600190505b858110156102ca57610253848461064a565b935061025f848c61064a565b935061026b878c61064a565b96506102778c886105b8565b9250610283848461061f565b93506102a9848e838151811061029c5761029b611069565b5b602002602001015161064a565b91506102b58286610686565b945080806102c2906110c7565b915050610241565b5083975050505050505050949350505050565b6000807f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001905060006103108686866106c2565b905060005b60208110156103745780600861032b919061110f565b8282602f6103399190611151565b6030811061034a57610349611069565b5b602002015160ff16901b8461035f9190611185565b9350808061036c906110c7565b915050610315565b50818361038191906111e8565b9250600080600090505b60108110156103ea578060086103a1919061110f565b8382600f6103af9190611151565b603081106103c0576103bf611069565b5b602002015160ff16901b826103d59190611185565b915080806103e2906110c7565b91505061038b565b5060007f0e0a77c19a07df2f666ea36f7879462e36fc76959f60cd29ac96341c4ffffffb9050838061041f5761041e6111b9565b5b81830991508380610433576104326111b9565b5b8286089450505050509392505050565b600081851061045157600080fd5b7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001841061047d57600080fd5b7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000183106104a957600080fd5b6104b3838661051f565b92506104bf84846105b8565b94506104cb848361051f565b93506104d88460016105b8565b93506104e382610a49565b91506104ef838361064a565b92506104fa85610a49565b9450610506838661064a565b9250610512838561064a565b9250829050949350505050565b6000806040518060c001604052806020815260200160208152602001602081526020018581526020018481526020017f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001815250905061057c610c49565b600060208260c08560055afa90508061059457600080fd5b816000600181106105a8576105a7611069565b5b6020020151935050505092915050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001806105e9576105e86111b9565b5b827f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000016106159190611151565b8408905092915050565b600080820361062d57600080fd5b61063682610a49565b9150610642838361064a565b905092915050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000018061067b5761067a6111b9565b5b828409905092915050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001806106b7576106b66111b9565b5b828408905092915050565b6106ca610c6b565b60606000806030905060006106de86610a94565b905060005b60408110156107235784846040516020016106ff9291906112cd565b6040516020818303038152906040529450808061071b906110c7565b9150506106e3565b508388888585878b8760405160200161074398979695949392919061135d565b6040516020818303038152906040529350600060028560405161076691906113e7565b602060405180830381855afa158015610783573d6000803e3d6000fd5b5050506040513d601f19601f820116820180604052508101906107a69190611434565b905080600188846040516020016107c09493929190611482565b604051602081830303815290604052945060006002866040516107e391906113e7565b602060405180830381855afa158015610800573d6000803e3d6000fd5b5050506040513d601f19601f820116820180604052508101906108239190611434565b905060005b60208110156108825781816020811061084457610843611069565b5b1a60f81b60f81c88826030811061085e5761085d611069565b5b602002019060ff16908160ff1681525050808061087a906110c7565b915050610828565b508060006020811061089757610896611069565b5b1a60f81b60f81c826000602081106108b2576108b1611069565b5b1a60f81b60f81c186040516020016108ca91906114cc565b60405160208183030381529060405295506000600190505b602081101561095657868282602081106108ff576108fe611069565b5b1a60f81b60f81c84836020811061091957610918611069565b5b1a60f81b60f81c186040516020016109329291906112cd565b6040516020818303038152906040529650808061094e906110c7565b9150506108e2565b50856002898560405160200161096f94939291906114e7565b604051602081830303815290604052955060028660405161099091906113e7565b602060405180830381855afa1580156109ad573d6000803e3d6000fd5b5050506040513d601f19601f820116820180604052508101906109d09190611434565b905060005b6010811015610a3b578181602081106109f1576109f0611069565b5b1a60f81b60f81c88602083610a069190611185565b60308110610a1757610a16611069565b5b602002019060ff16908160ff16815250508080610a33906110c7565b9150506109d5565b505050505050509392505050565b6000808203610a5757600080fd5b610a8d8260027f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001610a889190611151565b61051f565b9050919050565b60008060008084519050600092505b80821015610c3e576000858381518110610ac057610abf611069565b5b602001015160f81c60f81b9050608060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610b0f57600183610b089190611185565b9250610c2a565b60e060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610b5157600283610b4a9190611185565b9250610c29565b60f060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610b9357600383610b8c9190611185565b9250610c28565b60f8801b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610bd457600483610bcd9190611185565b9250610c27565b60fc60f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610c1657600583610c0f9190611185565b9250610c26565b600683610c239190611185565b92505b5b5b5b5b508280610c36906110c7565b935050610aa3565b829350505050919050565b6040518060200160405280600190602082028036833780820191505090505090565b604051806106000160405280603090602082028036833780820191505090505090565b6000604051905090565b600080fd5b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b610cf082610ca7565b810181811067ffffffffffffffff82111715610d0f57610d0e610cb8565b5b80604052505050565b6000610d22610c8e565b9050610d2e8282610ce7565b919050565b600067ffffffffffffffff821115610d4e57610d4d610cb8565b5b602082029050602081019050919050565b600080fd5b6000819050919050565b610d7781610d64565b8114610d8257600080fd5b50565b600081359050610d9481610d6e565b92915050565b6000610dad610da884610d33565b610d18565b90508083825260208201905060208402830185811115610dd057610dcf610d5f565b5b835b81811015610df95780610de58882610d85565b845260208401935050602081019050610dd2565b5050509392505050565b600082601f830112610e1857610e17610ca2565b5b8135610e28848260208601610d9a565b91505092915050565b60008060008060808587031215610e4b57610e4a610c98565b5b600085013567ffffffffffffffff811115610e6957610e68610c9d565b5b610e7587828801610e03565b9450506020610e8687828801610d85565b9350506040610e9787828801610d85565b9250506060610ea887828801610d85565b91505092959194509250565b610ebd81610d64565b82525050565b6000602082019050610ed86000830184610eb4565b92915050565b600080fd5b600067ffffffffffffffff821115610efe57610efd610cb8565b5b610f0782610ca7565b9050602081019050919050565b82818337600083830152505050565b6000610f36610f3184610ee3565b610d18565b905082815260208101848484011115610f5257610f51610ede565b5b610f5d848285610f14565b509392505050565b600082601f830112610f7a57610f79610ca2565b5b8135610f8a848260208601610f23565b91505092915050565b600080600060608486031215610fac57610fab610c98565b5b6000610fba86828701610d85565b9350506020610fcb86828701610d85565b925050604084013567ffffffffffffffff811115610fec57610feb610c9d565b5b610ff886828701610f65565b9150509250925092565b6000806000806080858703121561101c5761101b610c98565b5b600061102a87828801610d85565b945050602061103b87828801610d85565b935050604061104c87828801610d85565b925050606061105d87828801610d85565b91505092959194509250565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006110d282610d64565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff820361110457611103611098565b5b600182019050919050565b600061111a82610d64565b915061112583610d64565b925082820261113381610d64565b9150828204841483151761114a57611149611098565b5b5092915050565b600061115c82610d64565b915061116783610d64565b925082820390508181111561117f5761117e611098565b5b92915050565b600061119082610d64565b915061119b83610d64565b92508282019050808211156111b3576111b2611098565b5b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b60006111f382610d64565b91506111fe83610d64565b92508261120e5761120d6111b9565b5b828206905092915050565b600081519050919050565b600081905092915050565b60005b8381101561124d578082015181840152602081019050611232565b60008484015250505050565b600061126482611219565b61126e8185611224565b935061127e81856020860161122f565b80840191505092915050565b600060ff82169050919050565b60008160f81b9050919050565b60006112af82611297565b9050919050565b6112c76112c28261128a565b6112a4565b82525050565b60006112d98285611259565b91506112e582846112b6565b6001820191508190509392505050565b6000819050919050565b61131061130b82610d64565b6112f5565b82525050565b600081519050919050565b600081905092915050565b600061133782611316565b6113418185611321565b935061135181856020860161122f565b80840191505092915050565b6000611369828b611259565b9150611375828a6112ff565b60208201915061138582896112ff565b60208201915061139582886112b6565b6001820191506113a582876112b6565b6001820191506113b582866112b6565b6001820191506113c5828561132c565b91506113d182846112b6565b6001820191508190509998505050505050505050565b60006113f38284611259565b915081905092915050565b6000819050919050565b611411816113fe565b811461141c57600080fd5b50565b60008151905061142e81611408565b92915050565b60006020828403121561144a57611449610c98565b5b60006114588482850161141f565b91505092915050565b6000819050919050565b61147c611477826113fe565b611461565b82525050565b600061148e828761146b565b60208201915061149e82866112b6565b6001820191506114ae828561132c565b91506114ba82846112b6565b60018201915081905095945050505050565b60006114d882846112b6565b60018201915081905092915050565b60006114f38287611259565b91506114ff82866112b6565b60018201915061150f828561132c565b915061151b82846112b6565b6001820191508190509594505050505056fea2646970667358221220e0158b4546377b682ca9b20cc5a60f04f16a434cb80e6bbb655d6f3263bdd16c64736f6c63430008130033"

// DeployContract deploys a new Ethereum contract, binding an instance of Contract to it.
func DeployContract(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Contract, error) {
	parsed, err := abi.JSON(strings.NewReader(ContractABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}

	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(ContractBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Contract{ContractCaller: ContractCaller{contract: contract}, ContractTransactor: ContractTransactor{contract: contract}, ContractFilterer: ContractFilterer{contract: contract}}, nil
}

// Contract is an auto generated Go binding around an Ethereum contract.
type Contract struct {
	ContractCaller     // Read-only binding to the contract
	ContractTransactor // Write-only binding to the contract
	ContractFilterer   // Log filterer for contract events
}

// ContractCaller is an auto generated read-only Go binding around an Ethereum contract.
type ContractCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ContractTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ContractFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ContractSession struct {
	Contract     *Contract         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ContractCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ContractCallerSession struct {
	Contract *ContractCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// ContractTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ContractTransactorSession struct {
	Contract     *ContractTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// ContractRaw is an auto generated low-level Go binding around an Ethereum contract.
type ContractRaw struct {
	Contract *Contract // Generic contract binding to access the raw methods on
}

// ContractCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ContractCallerRaw struct {
	Contract *ContractCaller // Generic read-only contract binding to access the raw methods on
}

// ContractTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ContractTransactorRaw struct {
	Contract *ContractTransactor // Generic write-only contract binding to access the raw methods on
}

// NewContract creates a new instance of Contract, bound to a specific deployed contract.
func NewContract(address common.Address, backend bind.ContractBackend) (*Contract, error) {
	contract, err := bindContract(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Contract{ContractCaller: ContractCaller{contract: contract}, ContractTransactor: ContractTransactor{contract: contract}, ContractFilterer: ContractFilterer{contract: contract}}, nil
}

// NewContractCaller creates a new read-only instance of Contract, bound to a specific deployed contract.
func NewContractCaller(address common.Address, caller bind.ContractCaller) (*ContractCaller, error) {
	contract, err := bindContract(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ContractCaller{contract: contract}, nil
}

// NewContractTransactor creates a new write-only instance of Contract, bound to a specific deployed contract.
func NewContractTransactor(address common.Address, transactor bind.ContractTransactor) (*ContractTransactor, error) {
	contract, err := bindContract(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ContractTransactor{contract: contract}, nil
}

// NewContractFilterer creates a new log filterer instance of Contract, bound to a specific deployed contract.
func NewContractFilterer(address common.Address, filterer bind.ContractFilterer) (*ContractFilterer, error) {
	contract, err := bindContract(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ContractFilterer{contract: contract}, nil
}

// bindContract binds a generic wrapper to an already deployed contract.
func bindContract(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ContractABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Contract *ContractRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Contract.Contract.ContractCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Contract *ContractRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Contract.Contract.ContractTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Contract *ContractRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Contract.Contract.ContractTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Contract *ContractCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Contract.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Contract *ContractTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Contract.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Contract *ContractTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Contract.Contract.contract.Transact(opts, method, params...)
}

// TestComputeSumLiZi is a paid mutator transaction binding the contract method 0x437a9c6a.
//
// Solidity: function test_compute_sum_li_zi(uint256[] inputs, uint256 z, uint256 w, uint256 n) returns(uint256 res)
func (_Contract *ContractTransactor) TestComputeSumLiZi(opts *bind.TransactOpts, inputs []*big.Int, z *big.Int, w *big.Int, n *big.Int) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "test_compute_sum_li_zi", inputs, z, w, n)
}

// TestComputeSumLiZi is a paid mutator transaction binding the contract method 0x437a9c6a.
//
// Solidity: function test_compute_sum_li_zi(uint256[] inputs, uint256 z, uint256 w, uint256 n) returns(uint256 res)
func (_Contract *ContractSession) TestComputeSumLiZi(inputs []*big.Int, z *big.Int, w *big.Int, n *big.Int) (*types.Transaction, error) {
	return _Contract.Contract.TestComputeSumLiZi(&_Contract.TransactOpts, inputs, z, w, n)
}

// TestComputeSumLiZi is a paid mutator transaction binding the contract method 0x437a9c6a.
//
// Solidity: function test_compute_sum_li_zi(uint256[] inputs, uint256 z, uint256 w, uint256 n) returns(uint256 res)
func (_Contract *ContractTransactorSession) TestComputeSumLiZi(inputs []*big.Int, z *big.Int, w *big.Int, n *big.Int) (*types.Transaction, error) {
	return _Contract.Contract.TestComputeSumLiZi(&_Contract.TransactOpts, inputs, z, w, n)
}

// TestEvalIthLagrange is a paid mutator transaction binding the contract method 0xe0380a93.
//
// Solidity: function test_eval_ith_lagrange(uint256 i, uint256 z, uint256 w, uint256 n) returns(uint256 res)
func (_Contract *ContractTransactor) TestEvalIthLagrange(opts *bind.TransactOpts, i *big.Int, z *big.Int, w *big.Int, n *big.Int) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "test_eval_ith_lagrange", i, z, w, n)
}

// TestEvalIthLagrange is a paid mutator transaction binding the contract method 0xe0380a93.
//
// Solidity: function test_eval_ith_lagrange(uint256 i, uint256 z, uint256 w, uint256 n) returns(uint256 res)
func (_Contract *ContractSession) TestEvalIthLagrange(i *big.Int, z *big.Int, w *big.Int, n *big.Int) (*types.Transaction, error) {
	return _Contract.Contract.TestEvalIthLagrange(&_Contract.TransactOpts, i, z, w, n)
}

// TestEvalIthLagrange is a paid mutator transaction binding the contract method 0xe0380a93.
//
// Solidity: function test_eval_ith_lagrange(uint256 i, uint256 z, uint256 w, uint256 n) returns(uint256 res)
func (_Contract *ContractTransactorSession) TestEvalIthLagrange(i *big.Int, z *big.Int, w *big.Int, n *big.Int) (*types.Transaction, error) {
	return _Contract.Contract.TestEvalIthLagrange(&_Contract.TransactOpts, i, z, w, n)
}

// TestHash is a paid mutator transaction binding the contract method 0xc7baa217.
//
// Solidity: function test_hash(uint256 x, uint256 y, string dst) returns(uint256 res)
func (_Contract *ContractTransactor) TestHash(opts *bind.TransactOpts, x *big.Int, y *big.Int, dst string) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "test_hash", x, y, dst)
}

// TestHash is a paid mutator transaction binding the contract method 0xc7baa217.
//
// Solidity: function test_hash(uint256 x, uint256 y, string dst) returns(uint256 res)
func (_Contract *ContractSession) TestHash(x *big.Int, y *big.Int, dst string) (*types.Transaction, error) {
	return _Contract.Contract.TestHash(&_Contract.TransactOpts, x, y, dst)
}

// TestHash is a paid mutator transaction binding the contract method 0xc7baa217.
//
// Solidity: function test_hash(uint256 x, uint256 y, string dst) returns(uint256 res)
func (_Contract *ContractTransactorSession) TestHash(x *big.Int, y *big.Int, dst string) (*types.Transaction, error) {
	return _Contract.Contract.TestHash(&_Contract.TransactOpts, x, y, dst)
}

// ContractPrintUint256Iterator is returned from FilterPrintUint256 and is used to iterate over the raw logs and unpacked data for PrintUint256 events raised by the Contract contract.
type ContractPrintUint256Iterator struct {
	Event *ContractPrintUint256 // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ContractPrintUint256Iterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ContractPrintUint256)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ContractPrintUint256)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ContractPrintUint256Iterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ContractPrintUint256Iterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ContractPrintUint256 represents a PrintUint256 event raised by the Contract contract.
type ContractPrintUint256 struct {
	A   *big.Int
	Raw types.Log // Blockchain specific contextual infos
}

// FilterPrintUint256 is a free log retrieval operation binding the contract event 0xc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b.
//
// Solidity: event PrintUint256(uint256 a)
func (_Contract *ContractFilterer) FilterPrintUint256(opts *bind.FilterOpts) (*ContractPrintUint256Iterator, error) {

	logs, sub, err := _Contract.contract.FilterLogs(opts, "PrintUint256")
	if err != nil {
		return nil, err
	}
	return &ContractPrintUint256Iterator{contract: _Contract.contract, event: "PrintUint256", logs: logs, sub: sub}, nil
}

// WatchPrintUint256 is a free log subscription operation binding the contract event 0xc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b.
//
// Solidity: event PrintUint256(uint256 a)
func (_Contract *ContractFilterer) WatchPrintUint256(opts *bind.WatchOpts, sink chan<- *ContractPrintUint256) (event.Subscription, error) {

	logs, sub, err := _Contract.contract.WatchLogs(opts, "PrintUint256")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ContractPrintUint256)
				if err := _Contract.contract.UnpackLog(event, "PrintUint256", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParsePrintUint256 is a log parse operation binding the contract event 0xc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b.
//
// Solidity: event PrintUint256(uint256 a)
func (_Contract *ContractFilterer) ParsePrintUint256(log types.Log) (*ContractPrintUint256, error) {
	event := new(ContractPrintUint256)
	if err := _Contract.contract.UnpackLog(event, "PrintUint256", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
