// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contract

import (
	"errors"
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
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// ContractMetaData contains all meta data concerning the Contract contract.
var ContractMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"x\",\"type\":\"uint256\"}],\"name\":\"PrintUint256\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"proof\",\"type\":\"bytes\"},{\"internalType\":\"uint256[]\",\"name\":\"public_inputs\",\"type\":\"uint256[]\"}],\"name\":\"Verify\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"success\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Bin: "0x608060405234801561001057600080fd5b506104ec806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80637e4f7a8a14610030575b600080fd5b61004a600480360381019061004591906103cb565b610060565b6040516100579190610467565b60405180910390f35b60008060405160e08101600061007787878b6100fb565b9050610082816101c8565b905061008e818a61022f565b9050600083015193506102bf565b6040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152600c60248201527f6572726f722076657269667900000000000000000000000000000000000000006044820152606481fd5b600060405160e081016467616d6d6181527f2690e1e72a5d460791dc7f38d9132162db0620829611138940129de81e4032fb60208201527f23e245c5aa301a3000a25eda32818373fc1cf548138e41fa1ab4e805c18fd40d6040820152606081016020860280888337808201915060406000870183378060850160208482601b870160025afa8061018f5761018e61009c565b5b845196507f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001870660408701525050505050509392505050565b600060405160e060405101636265746181528360208201526020816024601c840160025afa806101fb576101fa61009c565b5b815193507f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000184066020840152505050919050565b600060405160e06040510164616c70686181526020810185815260208101905060016040028061010087018337808201915060406080870183378060650160208482601b870160025afa806102875761028661009c565b5b845196507f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000018706600087015250505050505092915050565b5050507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b816040516102f1919061049b565b60405180910390a16001915050949350505050565b600080fd5b600080fd5b600080fd5b600080fd5b600080fd5b60008083601f84011261033557610334610310565b5b8235905067ffffffffffffffff81111561035257610351610315565b5b60208301915083600182028301111561036e5761036d61031a565b5b9250929050565b60008083601f84011261038b5761038a610310565b5b8235905067ffffffffffffffff8111156103a8576103a7610315565b5b6020830191508360208202830111156103c4576103c361031a565b5b9250929050565b600080600080604085870312156103e5576103e4610306565b5b600085013567ffffffffffffffff8111156104035761040261030b565b5b61040f8782880161031f565b9450945050602085013567ffffffffffffffff8111156104325761043161030b565b5b61043e87828801610375565b925092505092959194509250565b60008115159050919050565b6104618161044c565b82525050565b600060208201905061047c6000830184610458565b92915050565b6000819050919050565b61049581610482565b82525050565b60006020820190506104b0600083018461048c565b9291505056fea264697066735822122017f28ad0c3889c274bc9a85c2b286937e6d6263be75b2a3f1e03293722868aac64736f6c63430008130033",
}

// ContractABI is the input ABI used to generate the binding from.
// Deprecated: Use ContractMetaData.ABI instead.
var ContractABI = ContractMetaData.ABI

// ContractBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use ContractMetaData.Bin instead.
var ContractBin = ContractMetaData.Bin

// DeployContract deploys a new Ethereum contract, binding an instance of Contract to it.
func DeployContract(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Contract, error) {
	parsed, err := ContractMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(ContractBin), backend)
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
	parsed, err := ContractMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
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

// Verify is a paid mutator transaction binding the contract method 0x7e4f7a8a.
//
// Solidity: function Verify(bytes proof, uint256[] public_inputs) returns(bool success)
func (_Contract *ContractTransactor) Verify(opts *bind.TransactOpts, proof []byte, public_inputs []*big.Int) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "Verify", proof, public_inputs)
}

// Verify is a paid mutator transaction binding the contract method 0x7e4f7a8a.
//
// Solidity: function Verify(bytes proof, uint256[] public_inputs) returns(bool success)
func (_Contract *ContractSession) Verify(proof []byte, public_inputs []*big.Int) (*types.Transaction, error) {
	return _Contract.Contract.Verify(&_Contract.TransactOpts, proof, public_inputs)
}

// Verify is a paid mutator transaction binding the contract method 0x7e4f7a8a.
//
// Solidity: function Verify(bytes proof, uint256[] public_inputs) returns(bool success)
func (_Contract *ContractTransactorSession) Verify(proof []byte, public_inputs []*big.Int) (*types.Transaction, error) {
	return _Contract.Contract.Verify(&_Contract.TransactOpts, proof, public_inputs)
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
	X   *big.Int
	Raw types.Log // Blockchain specific contextual infos
}

// FilterPrintUint256 is a free log retrieval operation binding the contract event 0xc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b.
//
// Solidity: event PrintUint256(uint256 x)
func (_Contract *ContractFilterer) FilterPrintUint256(opts *bind.FilterOpts) (*ContractPrintUint256Iterator, error) {

	logs, sub, err := _Contract.contract.FilterLogs(opts, "PrintUint256")
	if err != nil {
		return nil, err
	}
	return &ContractPrintUint256Iterator{contract: _Contract.contract, event: "PrintUint256", logs: logs, sub: sub}, nil
}

// WatchPrintUint256 is a free log subscription operation binding the contract event 0xc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b.
//
// Solidity: event PrintUint256(uint256 x)
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
// Solidity: event PrintUint256(uint256 x)
func (_Contract *ContractFilterer) ParsePrintUint256(log types.Log) (*ContractPrintUint256, error) {
	event := new(ContractPrintUint256)
	if err := _Contract.contract.UnpackLog(event, "PrintUint256", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
