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
const ContractABI = "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"a\",\"type\":\"uint256\"}],\"name\":\"PrintUint256\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"i\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"z\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"w\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"n\",\"type\":\"uint256\"}],\"name\":\"test_eval_ith_lagrange\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"res\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"x\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"y\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"dst\",\"type\":\"string\"}],\"name\":\"test_hash\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"res\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

// ContractBin is the compiled bytecode used for deploying new contracts.
var ContractBin = "0x608060405234801561001057600080fd5b50611286806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c8063c7baa2171461003b578063e0380a931461006b575b600080fd5b61005560048036038101906100509190610c8c565b61009b565b6040516100629190610d0a565b60405180910390f35b61008560048036038101906100809190610d25565b6100e8565b6040516100929190610d0a565b60405180910390f35b60006100a8848484610137565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b816040516100d99190610d0a565b60405180910390a19392505050565b60006100f68585858561029d565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b816040516101279190610d0a565b60405180910390a1949350505050565b6000807f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000019050600061016a868686610497565b905060005b60208110156101ce578060086101859190610dbb565b8282602f6101939190610dfd565b603081106101a4576101a3610e31565b5b602002015160ff16901b846101b99190610e60565b935080806101c690610e94565b91505061016f565b5081836101db9190610f0b565b9250600080600090505b6010811015610244578060086101fb9190610dbb565b8382600f6102099190610dfd565b6030811061021a57610219610e31565b5b602002015160ff16901b8261022f9190610e60565b9150808061023c90610e94565b9150506101e5565b5060007f0e0a77c19a07df2f666ea36f7879462e36fc76959f60cd29ac96341c4ffffffb9050838061027957610278610edc565b5b8183099150838061028d5761028c610edc565b5b8286089450505050509392505050565b60008185106102ab57600080fd5b7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000184106102d757600080fd5b7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001831061030357600080fd5b61030d838661081e565b92507f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000018061033e5761033d610edc565b5b837f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000161036a9190610dfd565b85089450610378848361081e565b93507f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001806103a9576103a8610edc565b5b60017f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000016103d69190610dfd565b850893506103e3826108b7565b91507f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000018061041457610413610edc565b5b8284099250610422856108b7565b94507f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000018061045357610452610edc565b5b85840992507f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000018061048757610486610edc565b5b8484099250829050949350505050565b61049f610ab7565b60606000806030905060006104b386610902565b905060005b60408110156104f85784846040516020016104d4929190610ff0565b604051602081830303815290604052945080806104f090610e94565b9150506104b8565b508388888585878b87604051602001610518989796959493929190611080565b6040516020818303038152906040529350600060028560405161053b919061110a565b602060405180830381855afa158015610558573d6000803e3d6000fd5b5050506040513d601f19601f8201168201806040525081019061057b9190611157565b9050806001888460405160200161059594939291906111a5565b604051602081830303815290604052945060006002866040516105b8919061110a565b602060405180830381855afa1580156105d5573d6000803e3d6000fd5b5050506040513d601f19601f820116820180604052508101906105f89190611157565b905060005b60208110156106575781816020811061061957610618610e31565b5b1a60f81b60f81c88826030811061063357610632610e31565b5b602002019060ff16908160ff1681525050808061064f90610e94565b9150506105fd565b508060006020811061066c5761066b610e31565b5b1a60f81b60f81c8260006020811061068757610686610e31565b5b1a60f81b60f81c1860405160200161069f91906111ef565b60405160208183030381529060405295506000600190505b602081101561072b57868282602081106106d4576106d3610e31565b5b1a60f81b60f81c8483602081106106ee576106ed610e31565b5b1a60f81b60f81c18604051602001610707929190610ff0565b6040516020818303038152906040529650808061072390610e94565b9150506106b7565b508560028985604051602001610744949392919061120a565b6040516020818303038152906040529550600286604051610765919061110a565b602060405180830381855afa158015610782573d6000803e3d6000fd5b5050506040513d601f19601f820116820180604052508101906107a59190611157565b905060005b6010811015610810578181602081106107c6576107c5610e31565b5b1a60f81b60f81c886020836107db9190610e60565b603081106107ec576107eb610e31565b5b602002019060ff16908160ff1681525050808061080890610e94565b9150506107aa565b505050505050509392505050565b6000806040518060c001604052806020815260200160208152602001602081526020018581526020018481526020017f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001815250905061087b610ada565b600060208260c08560055afa90508061089357600080fd5b816000600181106108a7576108a6610e31565b5b6020020151935050505092915050565b60008082036108c557600080fd5b6108fb8260027f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000016108f69190610dfd565b61081e565b9050919050565b60008060008084519050600092505b80821015610aac57600085838151811061092e5761092d610e31565b5b602001015160f81c60f81b9050608060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916101561097d576001836109769190610e60565b9250610a98565b60e060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191610156109bf576002836109b89190610e60565b9250610a97565b60f060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610a01576003836109fa9190610e60565b9250610a96565b60f8801b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610a4257600483610a3b9190610e60565b9250610a95565b60fc60f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610a8457600583610a7d9190610e60565b9250610a94565b600683610a919190610e60565b92505b5b5b5b5b508280610aa490610e94565b935050610911565b829350505050919050565b604051806106000160405280603090602082028036833780820191505090505090565b6040518060200160405280600190602082028036833780820191505090505090565b6000604051905090565b600080fd5b600080fd5b6000819050919050565b610b2381610b10565b8114610b2e57600080fd5b50565b600081359050610b4081610b1a565b92915050565b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b610b9982610b50565b810181811067ffffffffffffffff82111715610bb857610bb7610b61565b5b80604052505050565b6000610bcb610afc565b9050610bd78282610b90565b919050565b600067ffffffffffffffff821115610bf757610bf6610b61565b5b610c0082610b50565b9050602081019050919050565b82818337600083830152505050565b6000610c2f610c2a84610bdc565b610bc1565b905082815260208101848484011115610c4b57610c4a610b4b565b5b610c56848285610c0d565b509392505050565b600082601f830112610c7357610c72610b46565b5b8135610c83848260208601610c1c565b91505092915050565b600080600060608486031215610ca557610ca4610b06565b5b6000610cb386828701610b31565b9350506020610cc486828701610b31565b925050604084013567ffffffffffffffff811115610ce557610ce4610b0b565b5b610cf186828701610c5e565b9150509250925092565b610d0481610b10565b82525050565b6000602082019050610d1f6000830184610cfb565b92915050565b60008060008060808587031215610d3f57610d3e610b06565b5b6000610d4d87828801610b31565b9450506020610d5e87828801610b31565b9350506040610d6f87828801610b31565b9250506060610d8087828801610b31565b91505092959194509250565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000610dc682610b10565b9150610dd183610b10565b9250828202610ddf81610b10565b91508282048414831517610df657610df5610d8c565b5b5092915050565b6000610e0882610b10565b9150610e1383610b10565b9250828203905081811115610e2b57610e2a610d8c565b5b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6000610e6b82610b10565b9150610e7683610b10565b9250828201905080821115610e8e57610e8d610d8c565b5b92915050565b6000610e9f82610b10565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203610ed157610ed0610d8c565b5b600182019050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b6000610f1682610b10565b9150610f2183610b10565b925082610f3157610f30610edc565b5b828206905092915050565b600081519050919050565b600081905092915050565b60005b83811015610f70578082015181840152602081019050610f55565b60008484015250505050565b6000610f8782610f3c565b610f918185610f47565b9350610fa1818560208601610f52565b80840191505092915050565b600060ff82169050919050565b60008160f81b9050919050565b6000610fd282610fba565b9050919050565b610fea610fe582610fad565b610fc7565b82525050565b6000610ffc8285610f7c565b91506110088284610fd9565b6001820191508190509392505050565b6000819050919050565b61103361102e82610b10565b611018565b82525050565b600081519050919050565b600081905092915050565b600061105a82611039565b6110648185611044565b9350611074818560208601610f52565b80840191505092915050565b600061108c828b610f7c565b9150611098828a611022565b6020820191506110a88289611022565b6020820191506110b88288610fd9565b6001820191506110c88287610fd9565b6001820191506110d88286610fd9565b6001820191506110e8828561104f565b91506110f48284610fd9565b6001820191508190509998505050505050505050565b60006111168284610f7c565b915081905092915050565b6000819050919050565b61113481611121565b811461113f57600080fd5b50565b6000815190506111518161112b565b92915050565b60006020828403121561116d5761116c610b06565b5b600061117b84828501611142565b91505092915050565b6000819050919050565b61119f61119a82611121565b611184565b82525050565b60006111b1828761118e565b6020820191506111c18286610fd9565b6001820191506111d1828561104f565b91506111dd8284610fd9565b60018201915081905095945050505050565b60006111fb8284610fd9565b60018201915081905092915050565b60006112168287610f7c565b91506112228286610fd9565b600182019150611232828561104f565b915061123e8284610fd9565b6001820191508190509594505050505056fea2646970667358221220ea479734a01c3e5a56fdf85b6d2529e45e398f0a30e7e3b03464878bf38b282e64736f6c63430008130033"

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
