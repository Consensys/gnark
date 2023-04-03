// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package hashfr

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

// HashFrABI is the input ABI used to generate the binding from.
const HashFrABI = "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"a\",\"type\":\"uint256\"}],\"name\":\"PrintUint256\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"x\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"y\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"dst\",\"type\":\"string\"}],\"name\":\"test_hash\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"res\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

// HashFrBin is the compiled bytecode used for deploying new contracts.
var HashFrBin = "0x608060405234801561001057600080fd5b50610e95806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063c7baa21714610030575b600080fd5b61004a60048036038101906100459190610902565b610060565b6040516100579190610980565b60405180910390f35b600061006d8484846100ad565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b8160405161009e9190610980565b60405180910390a19392505050565b6000807f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001905060006100e0868686610213565b905060005b6020811015610144578060086100fb91906109ca565b8282602f6101099190610a0c565b6030811061011a57610119610a40565b5b602002015160ff16901b8461012f9190610a6f565b9350808061013c90610aa3565b9150506100e5565b5081836101519190610b1a565b9250600080600090505b60108110156101ba5780600861017191906109ca565b8382600f61017f9190610a0c565b603081106101905761018f610a40565b5b602002015160ff16901b826101a59190610a6f565b915080806101b290610aa3565b91505061015b565b5060007f0e0a77c19a07df2f666ea36f7879462e36fc76959f60cd29ac96341c4ffffffb905083806101ef576101ee610aeb565b5b8183099150838061020357610202610aeb565b5b8286089450505050509392505050565b61021b61074f565b606060008060309050600061022f8661059a565b905060005b6040811015610274578484604051602001610250929190610bff565b6040516020818303038152906040529450808061026c90610aa3565b915050610234565b508388888585878b87604051602001610294989796959493929190610c8f565b604051602081830303815290604052935060006002856040516102b79190610d19565b602060405180830381855afa1580156102d4573d6000803e3d6000fd5b5050506040513d601f19601f820116820180604052508101906102f79190610d66565b905080600188846040516020016103119493929190610db4565b604051602081830303815290604052945060006002866040516103349190610d19565b602060405180830381855afa158015610351573d6000803e3d6000fd5b5050506040513d601f19601f820116820180604052508101906103749190610d66565b905060005b60208110156103d35781816020811061039557610394610a40565b5b1a60f81b60f81c8882603081106103af576103ae610a40565b5b602002019060ff16908160ff168152505080806103cb90610aa3565b915050610379565b50806000602081106103e8576103e7610a40565b5b1a60f81b60f81c8260006020811061040357610402610a40565b5b1a60f81b60f81c1860405160200161041b9190610dfe565b60405160208183030381529060405295506000600190505b60208110156104a757868282602081106104505761044f610a40565b5b1a60f81b60f81c84836020811061046a57610469610a40565b5b1a60f81b60f81c18604051602001610483929190610bff565b6040516020818303038152906040529650808061049f90610aa3565b915050610433565b5085600289856040516020016104c09493929190610e19565b60405160208183030381529060405295506002866040516104e19190610d19565b602060405180830381855afa1580156104fe573d6000803e3d6000fd5b5050506040513d601f19601f820116820180604052508101906105219190610d66565b905060005b601081101561058c5781816020811061054257610541610a40565b5b1a60f81b60f81c886020836105579190610a6f565b6030811061056857610567610a40565b5b602002019060ff16908160ff1681525050808061058490610aa3565b915050610526565b505050505050509392505050565b60008060008084519050600092505b808210156107445760008583815181106105c6576105c5610a40565b5b602001015160f81c60f81b9050608060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191610156106155760018361060e9190610a6f565b9250610730565b60e060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610657576002836106509190610a6f565b925061072f565b60f060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610699576003836106929190610a6f565b925061072e565b60f8801b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191610156106da576004836106d39190610a6f565b925061072d565b60fc60f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916101561071c576005836107159190610a6f565b925061072c565b6006836107299190610a6f565b92505b5b5b5b5b50828061073c90610aa3565b9350506105a9565b829350505050919050565b604051806106000160405280603090602082028036833780820191505090505090565b6000604051905090565b600080fd5b600080fd5b6000819050919050565b61079981610786565b81146107a457600080fd5b50565b6000813590506107b681610790565b92915050565b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b61080f826107c6565b810181811067ffffffffffffffff8211171561082e5761082d6107d7565b5b80604052505050565b6000610841610772565b905061084d8282610806565b919050565b600067ffffffffffffffff82111561086d5761086c6107d7565b5b610876826107c6565b9050602081019050919050565b82818337600083830152505050565b60006108a56108a084610852565b610837565b9050828152602081018484840111156108c1576108c06107c1565b5b6108cc848285610883565b509392505050565b600082601f8301126108e9576108e86107bc565b5b81356108f9848260208601610892565b91505092915050565b60008060006060848603121561091b5761091a61077c565b5b6000610929868287016107a7565b935050602061093a868287016107a7565b925050604084013567ffffffffffffffff81111561095b5761095a610781565b5b610967868287016108d4565b9150509250925092565b61097a81610786565b82525050565b60006020820190506109956000830184610971565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006109d582610786565b91506109e083610786565b92508282026109ee81610786565b91508282048414831517610a0557610a0461099b565b5b5092915050565b6000610a1782610786565b9150610a2283610786565b9250828203905081811115610a3a57610a3961099b565b5b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6000610a7a82610786565b9150610a8583610786565b9250828201905080821115610a9d57610a9c61099b565b5b92915050565b6000610aae82610786565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203610ae057610adf61099b565b5b600182019050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b6000610b2582610786565b9150610b3083610786565b925082610b4057610b3f610aeb565b5b828206905092915050565b600081519050919050565b600081905092915050565b60005b83811015610b7f578082015181840152602081019050610b64565b60008484015250505050565b6000610b9682610b4b565b610ba08185610b56565b9350610bb0818560208601610b61565b80840191505092915050565b600060ff82169050919050565b60008160f81b9050919050565b6000610be182610bc9565b9050919050565b610bf9610bf482610bbc565b610bd6565b82525050565b6000610c0b8285610b8b565b9150610c178284610be8565b6001820191508190509392505050565b6000819050919050565b610c42610c3d82610786565b610c27565b82525050565b600081519050919050565b600081905092915050565b6000610c6982610c48565b610c738185610c53565b9350610c83818560208601610b61565b80840191505092915050565b6000610c9b828b610b8b565b9150610ca7828a610c31565b602082019150610cb78289610c31565b602082019150610cc78288610be8565b600182019150610cd78287610be8565b600182019150610ce78286610be8565b600182019150610cf78285610c5e565b9150610d038284610be8565b6001820191508190509998505050505050505050565b6000610d258284610b8b565b915081905092915050565b6000819050919050565b610d4381610d30565b8114610d4e57600080fd5b50565b600081519050610d6081610d3a565b92915050565b600060208284031215610d7c57610d7b61077c565b5b6000610d8a84828501610d51565b91505092915050565b6000819050919050565b610dae610da982610d30565b610d93565b82525050565b6000610dc08287610d9d565b602082019150610dd08286610be8565b600182019150610de08285610c5e565b9150610dec8284610be8565b60018201915081905095945050505050565b6000610e0a8284610be8565b60018201915081905092915050565b6000610e258287610b8b565b9150610e318286610be8565b600182019150610e418285610c5e565b9150610e4d8284610be8565b6001820191508190509594505050505056fea2646970667358221220e4fc454c7ba0fb4880fefe31ca544602ef15813a7689c5a4c4f5b52931d0dfa564736f6c63430008130033"

// DeployHashFr deploys a new Ethereum contract, binding an instance of HashFr to it.
func DeployHashFr(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *HashFr, error) {
	parsed, err := abi.JSON(strings.NewReader(HashFrABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}

	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(HashFrBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &HashFr{HashFrCaller: HashFrCaller{contract: contract}, HashFrTransactor: HashFrTransactor{contract: contract}, HashFrFilterer: HashFrFilterer{contract: contract}}, nil
}

// HashFr is an auto generated Go binding around an Ethereum contract.
type HashFr struct {
	HashFrCaller     // Read-only binding to the contract
	HashFrTransactor // Write-only binding to the contract
	HashFrFilterer   // Log filterer for contract events
}

// HashFrCaller is an auto generated read-only Go binding around an Ethereum contract.
type HashFrCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// HashFrTransactor is an auto generated write-only Go binding around an Ethereum contract.
type HashFrTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// HashFrFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type HashFrFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// HashFrSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type HashFrSession struct {
	Contract     *HashFr           // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// HashFrCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type HashFrCallerSession struct {
	Contract *HashFrCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts // Call options to use throughout this session
}

// HashFrTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type HashFrTransactorSession struct {
	Contract     *HashFrTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// HashFrRaw is an auto generated low-level Go binding around an Ethereum contract.
type HashFrRaw struct {
	Contract *HashFr // Generic contract binding to access the raw methods on
}

// HashFrCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type HashFrCallerRaw struct {
	Contract *HashFrCaller // Generic read-only contract binding to access the raw methods on
}

// HashFrTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type HashFrTransactorRaw struct {
	Contract *HashFrTransactor // Generic write-only contract binding to access the raw methods on
}

// NewHashFr creates a new instance of HashFr, bound to a specific deployed contract.
func NewHashFr(address common.Address, backend bind.ContractBackend) (*HashFr, error) {
	contract, err := bindHashFr(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &HashFr{HashFrCaller: HashFrCaller{contract: contract}, HashFrTransactor: HashFrTransactor{contract: contract}, HashFrFilterer: HashFrFilterer{contract: contract}}, nil
}

// NewHashFrCaller creates a new read-only instance of HashFr, bound to a specific deployed contract.
func NewHashFrCaller(address common.Address, caller bind.ContractCaller) (*HashFrCaller, error) {
	contract, err := bindHashFr(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &HashFrCaller{contract: contract}, nil
}

// NewHashFrTransactor creates a new write-only instance of HashFr, bound to a specific deployed contract.
func NewHashFrTransactor(address common.Address, transactor bind.ContractTransactor) (*HashFrTransactor, error) {
	contract, err := bindHashFr(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &HashFrTransactor{contract: contract}, nil
}

// NewHashFrFilterer creates a new log filterer instance of HashFr, bound to a specific deployed contract.
func NewHashFrFilterer(address common.Address, filterer bind.ContractFilterer) (*HashFrFilterer, error) {
	contract, err := bindHashFr(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &HashFrFilterer{contract: contract}, nil
}

// bindHashFr binds a generic wrapper to an already deployed contract.
func bindHashFr(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(HashFrABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_HashFr *HashFrRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _HashFr.Contract.HashFrCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_HashFr *HashFrRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _HashFr.Contract.HashFrTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_HashFr *HashFrRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _HashFr.Contract.HashFrTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_HashFr *HashFrCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _HashFr.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_HashFr *HashFrTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _HashFr.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_HashFr *HashFrTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _HashFr.Contract.contract.Transact(opts, method, params...)
}

// TestHash is a paid mutator transaction binding the contract method 0xc7baa217.
//
// Solidity: function test_hash(uint256 x, uint256 y, string dst) returns(uint256 res)
func (_HashFr *HashFrTransactor) TestHash(opts *bind.TransactOpts, x *big.Int, y *big.Int, dst string) (*types.Transaction, error) {
	return _HashFr.contract.Transact(opts, "test_hash", x, y, dst)
}

// TestHash is a paid mutator transaction binding the contract method 0xc7baa217.
//
// Solidity: function test_hash(uint256 x, uint256 y, string dst) returns(uint256 res)
func (_HashFr *HashFrSession) TestHash(x *big.Int, y *big.Int, dst string) (*types.Transaction, error) {
	return _HashFr.Contract.TestHash(&_HashFr.TransactOpts, x, y, dst)
}

// TestHash is a paid mutator transaction binding the contract method 0xc7baa217.
//
// Solidity: function test_hash(uint256 x, uint256 y, string dst) returns(uint256 res)
func (_HashFr *HashFrTransactorSession) TestHash(x *big.Int, y *big.Int, dst string) (*types.Transaction, error) {
	return _HashFr.Contract.TestHash(&_HashFr.TransactOpts, x, y, dst)
}

// HashFrPrintUint256Iterator is returned from FilterPrintUint256 and is used to iterate over the raw logs and unpacked data for PrintUint256 events raised by the HashFr contract.
type HashFrPrintUint256Iterator struct {
	Event *HashFrPrintUint256 // Event containing the contract specifics and raw log

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
func (it *HashFrPrintUint256Iterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(HashFrPrintUint256)
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
		it.Event = new(HashFrPrintUint256)
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
func (it *HashFrPrintUint256Iterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *HashFrPrintUint256Iterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// HashFrPrintUint256 represents a PrintUint256 event raised by the HashFr contract.
type HashFrPrintUint256 struct {
	A   *big.Int
	Raw types.Log // Blockchain specific contextual infos
}

// FilterPrintUint256 is a free log retrieval operation binding the contract event 0xc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b.
//
// Solidity: event PrintUint256(uint256 a)
func (_HashFr *HashFrFilterer) FilterPrintUint256(opts *bind.FilterOpts) (*HashFrPrintUint256Iterator, error) {

	logs, sub, err := _HashFr.contract.FilterLogs(opts, "PrintUint256")
	if err != nil {
		return nil, err
	}
	return &HashFrPrintUint256Iterator{contract: _HashFr.contract, event: "PrintUint256", logs: logs, sub: sub}, nil
}

// WatchPrintUint256 is a free log subscription operation binding the contract event 0xc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b.
//
// Solidity: event PrintUint256(uint256 a)
func (_HashFr *HashFrFilterer) WatchPrintUint256(opts *bind.WatchOpts, sink chan<- *HashFrPrintUint256) (event.Subscription, error) {

	logs, sub, err := _HashFr.contract.WatchLogs(opts, "PrintUint256")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(HashFrPrintUint256)
				if err := _HashFr.contract.UnpackLog(event, "PrintUint256", log); err != nil {
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
func (_HashFr *HashFrFilterer) ParsePrintUint256(log types.Log) (*HashFrPrintUint256, error) {
	event := new(HashFrPrintUint256)
	if err := _HashFr.contract.UnpackLog(event, "PrintUint256", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
