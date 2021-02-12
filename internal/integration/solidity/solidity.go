// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package solidity

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

// PairingABI is the input ABI used to generate the binding from.
const PairingABI = "[]"

// PairingBin is the compiled bytecode used for deploying new contracts.
var PairingBin = "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea264697066735822122046670d5204d6a472c4e4798a7cf6e3fb86cfeac79c8f187d53ee09376941aede64736f6c63430008010033"

// DeployPairing deploys a new Ethereum contract, binding an instance of Pairing to it.
func DeployPairing(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Pairing, error) {
	parsed, err := abi.JSON(strings.NewReader(PairingABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}

	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(PairingBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Pairing{PairingCaller: PairingCaller{contract: contract}, PairingTransactor: PairingTransactor{contract: contract}, PairingFilterer: PairingFilterer{contract: contract}}, nil
}

// Pairing is an auto generated Go binding around an Ethereum contract.
type Pairing struct {
	PairingCaller     // Read-only binding to the contract
	PairingTransactor // Write-only binding to the contract
	PairingFilterer   // Log filterer for contract events
}

// PairingCaller is an auto generated read-only Go binding around an Ethereum contract.
type PairingCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PairingTransactor is an auto generated write-only Go binding around an Ethereum contract.
type PairingTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PairingFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type PairingFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// PairingSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type PairingSession struct {
	Contract     *Pairing          // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// PairingCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type PairingCallerSession struct {
	Contract *PairingCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts  // Call options to use throughout this session
}

// PairingTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type PairingTransactorSession struct {
	Contract     *PairingTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// PairingRaw is an auto generated low-level Go binding around an Ethereum contract.
type PairingRaw struct {
	Contract *Pairing // Generic contract binding to access the raw methods on
}

// PairingCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type PairingCallerRaw struct {
	Contract *PairingCaller // Generic read-only contract binding to access the raw methods on
}

// PairingTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type PairingTransactorRaw struct {
	Contract *PairingTransactor // Generic write-only contract binding to access the raw methods on
}

// NewPairing creates a new instance of Pairing, bound to a specific deployed contract.
func NewPairing(address common.Address, backend bind.ContractBackend) (*Pairing, error) {
	contract, err := bindPairing(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Pairing{PairingCaller: PairingCaller{contract: contract}, PairingTransactor: PairingTransactor{contract: contract}, PairingFilterer: PairingFilterer{contract: contract}}, nil
}

// NewPairingCaller creates a new read-only instance of Pairing, bound to a specific deployed contract.
func NewPairingCaller(address common.Address, caller bind.ContractCaller) (*PairingCaller, error) {
	contract, err := bindPairing(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &PairingCaller{contract: contract}, nil
}

// NewPairingTransactor creates a new write-only instance of Pairing, bound to a specific deployed contract.
func NewPairingTransactor(address common.Address, transactor bind.ContractTransactor) (*PairingTransactor, error) {
	contract, err := bindPairing(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &PairingTransactor{contract: contract}, nil
}

// NewPairingFilterer creates a new log filterer instance of Pairing, bound to a specific deployed contract.
func NewPairingFilterer(address common.Address, filterer bind.ContractFilterer) (*PairingFilterer, error) {
	contract, err := bindPairing(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &PairingFilterer{contract: contract}, nil
}

// bindPairing binds a generic wrapper to an already deployed contract.
func bindPairing(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(PairingABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Pairing *PairingRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Pairing.Contract.PairingCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Pairing *PairingRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Pairing.Contract.PairingTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Pairing *PairingRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Pairing.Contract.PairingTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Pairing *PairingCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Pairing.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Pairing *PairingTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Pairing.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Pairing *PairingTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Pairing.Contract.contract.Transact(opts, method, params...)
}

// VerifierABI is the input ABI used to generate the binding from.
const VerifierABI = "[{\"inputs\":[{\"internalType\":\"uint256[2]\",\"name\":\"a\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[2][2]\",\"name\":\"b\",\"type\":\"uint256[2][2]\"},{\"internalType\":\"uint256[2]\",\"name\":\"c\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[1]\",\"name\":\"input\",\"type\":\"uint256[1]\"}],\"name\":\"verifyProof\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"r\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]"

// VerifierFuncSigs maps the 4-byte function signature to its string representation.
var VerifierFuncSigs = map[string]string{
	"43753b4d": "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[1])",
}

// VerifierBin is the compiled bytecode used for deploying new contracts.
var VerifierBin = "0x608060405234801561001057600080fd5b50611261806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c806343753b4d14610030575b600080fd5b61004361003e366004610dd3565b610059565b6040516100509190610e83565b60405180910390f35b6000610063610bce565b6040805180820182528751815260208089015181830152908352815160808101835287515181840190815288518301516060830152815282518084018452888301805151825251830151818401528183015283820152815180830183528651815286820151918101919091529082015260006100dd6103dc565b60408051808201909152600080825260208201528351519192509060008051602061120c8339815191521161012d5760405162461bcd60e51b815260040161012490610ec5565b60405180910390fd5b82516020015160008051602061120c8339815191521161015f5760405162461bcd60e51b81526004016101249061103b565b6020830151515160008051602061120c833981519152116101925760405162461bcd60e51b815260040161012490610e8e565b60208381015101515160008051602061120c833981519152116101c75760405162461bcd60e51b815260040161012490611004565b60208381015151015160008051602061120c833981519152116101fc5760405162461bcd60e51b815260040161012490610f33565b602083810151810151015160008051602061120c833981519152116102335760405162461bcd60e51b815260040161012490610efc565b60408301515160008051602061120c833981519152116102655760405162461bcd60e51b81526004016101249061109e565b60008051602061120c8339815191528360400151602001511061029a5760405162461bcd60e51b815260040161012490610f96565b60005b6001811015610388577f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000018682600181106102e757634e487b7160e01b600052603260045260246000fd5b6020020151106103095760405162461bcd60e51b815260040161012490610fcd565b6103748261036f85608001518460016103229190611156565b6002811061034057634e487b7160e01b600052603260045260246000fd5b602002015189856001811061036557634e487b7160e01b600052603260045260246000fd5b60200201516106fd565b610768565b915080610380816111a4565b91505061029d565b5060808201515161039a908290610768565b90506103d06103ac84600001516107cf565b8460200151846000015185602001518587604001518960400151896060015161085c565b98975050505050505050565b6103e4610c00565b6040805180820182527f0eab182bc78f8e79c90cdfde79e243535c085755d098ae5f848723c4a77414fd81527f2b566a98383cc2f64834623968e8b24f47d4bd020cf70eff5d29f2f386e2d2116020808301919091529083528151608080820184527f0f1c2f6bf689bb2983cbeb922473e94266363839b77c5c80ff030ecaef90c8a28285019081527f145c41631d618a9e059262bef5c2ed922fb465ad5cce2bab8f070cad672a131d606080850191909152908352845180860186527f0806384615c958e99cdc71a1e1c48bfbf156070f6feabe46b3f180af1e4fd65f81527f1a46ebf1f6296af1090ce515c7fad607301e7bf99ddd69a57c20ffb55c6db944818601528385015285840192909252835180820185527f1854b5d7a13390e2ccdc10d0aebc7cbe7c1d6d1c43edd04a4fdde9c5993921a08186019081527f14e9a3798242a9483976dde9655549f157d2a597e5da3e57c0f7e86569d6e6d7828501528152845180860186527f174218b284f5c9ec7689e514a3778ac68b6f1733a9d4399af83f94f8331a62e981527f07662aecde9a8cbfa392bf3d90fc03c2474b053669245e4211bd582611ea1662818601528185015285850152835180820185527f139742fc39df8f4768739d4808149a568b5c183e58b865d7afa7e284963adc6e8186019081527f1ded4dad15839ecc53fc2a2213063fc62645c4feb8fd4ba2e88915b173cd765f828501528152845180860186527f17c98db9627f74953ed7c103694c46f7582d17772a042e049916abe4ea26c9f881527f173fc6b50bd53e24f461364969ded2248c8083c84ad27d7af7563ac4059b063a818601528185015291850191909152825180840184527f03ece776f1d8d79b60d6a72ad6b0613af04bb9d370146abd2bb4423a4b6b820781527f2661cdd8596f07ff1c79a319a7b89a50f227b6c170a26d227db4742a679f74e28184015290840180519190915282518084019093527f1da8a5feb4f767c002f85b0a6b4b20f14e2fc860b28adad641fff11702e98ae283527f0ff0282072de52fbd5109cfb637c4a3e10928066a4a4607ab170a462822918ee8383015251015290565b610705610c47565b61070d610c61565b835181526020808501519082015260408101839052600060608360808460076107d05a03fa905080801561074057610742565bfe5b50806107605760405162461bcd60e51b815260040161012490610f6a565b505092915050565b610770610c47565b610778610c7f565b8351815260208085015181830152835160408301528301516060808301919091526000908360c08460066107d05a03fa90508080156107405750806107605760405162461bcd60e51b815260040161012490611072565b6107d7610c47565b81511580156107e857506020820151155b1561080757506040805180820190915260008082526020820152610857565b60405180604001604052808360000151815260200160008051602061120c833981519152846020015161083a91906111bf565b6108529060008051602061120c83398151915261118d565b905290505b919050565b60408051608080820183528a825260208083018a90528284018890526060808401879052845192830185528b83528282018a9052828501889052820185905283516018808252610320820190955260009491859190839082016103008036833701905050905060005b6004811015610b745760006108db82600661116e565b90508582600481106108fd57634e487b7160e01b600052603260045260246000fd5b6020020151518361090f836000611156565b8151811061092d57634e487b7160e01b600052603260045260246000fd5b60200260200101818152505085826004811061095957634e487b7160e01b600052603260045260246000fd5b602002015160200151838260016109709190611156565b8151811061098e57634e487b7160e01b600052603260045260246000fd5b6020026020010181815250508482600481106109ba57634e487b7160e01b600052603260045260246000fd5b60200201515151836109cd836002611156565b815181106109eb57634e487b7160e01b600052603260045260246000fd5b602002602001018181525050848260048110610a1757634e487b7160e01b600052603260045260246000fd5b6020020151516001602002015183610a30836003611156565b81518110610a4e57634e487b7160e01b600052603260045260246000fd5b602002602001018181525050848260048110610a7a57634e487b7160e01b600052603260045260246000fd5b602002015160200151600060028110610aa357634e487b7160e01b600052603260045260246000fd5b602002015183610ab4836004611156565b81518110610ad257634e487b7160e01b600052603260045260246000fd5b602002602001018181525050848260048110610afe57634e487b7160e01b600052603260045260246000fd5b602002015160200151600160028110610b2757634e487b7160e01b600052603260045260246000fd5b602002015183610b38836005611156565b81518110610b5657634e487b7160e01b600052603260045260246000fd5b60209081029190910101525080610b6c816111a4565b9150506108c5565b50610b7d610c9d565b6000602082602086026020860160086107d05a03fa9050808015610740575080610bb95760405162461bcd60e51b8152600401610124906110d5565b505115159d9c50505050505050505050505050565b6040518060600160405280610be1610c47565b8152602001610bee610cbb565b8152602001610bfb610c47565b905290565b6040518060a00160405280610c13610c47565b8152602001610c20610cbb565b8152602001610c2d610cbb565b8152602001610c3a610cbb565b8152602001610bfb610cdb565b604051806040016040528060008152602001600081525090565b60405180606001604052806003906020820280368337509192915050565b60405180608001604052806004906020820280368337509192915050565b60405180602001604052806001906020820280368337509192915050565b6040518060400160405280610cce610d08565b8152602001610bfb610d08565b60405180604001604052806002905b610cf2610c47565b815260200190600190039081610cea5790505090565b60405180604001604052806002906020820280368337509192915050565b600082601f830112610d36578081fd5b6020610d4181611104565b8084868487011115610d51578485fd5b845b6001811015610d7057813584529284019290840190600101610d53565b50909695505050505050565b600082601f830112610d8c578081fd5b610d966040611104565b808385604086011115610da7578384fd5b835b6002811015610dc8578135845260209384019390910190600101610da9565b509095945050505050565b6000806000806101208587031215610de9578384fd5b610df38686610d7c565b9350604086605f870112610e05578384fd5b6002610e18610e1382611135565b611104565b8083890160c08a018b811115610e2c578889fd5b885b85811015610e5457610e408d84610d7c565b855260209094019391860191600101610e2e565b50829850610e628c82610d7c565b9750505050505050610e78866101008701610d26565b905092959194509250565b901515815260200190565b60208082526018908201527f76657269666965722d6258302d6774652d7072696d652d710000000000000000604082015260600190565b60208082526017908201527f76657269666965722d61582d6774652d7072696d652d71000000000000000000604082015260600190565b60208082526018908201527f76657269666965722d6259312d6774652d7072696d652d710000000000000000604082015260600190565b60208082526018908201527f76657269666965722d6258312d6774652d7072696d652d710000000000000000604082015260600190565b6020808252601290820152711c185a5c9a5b99cb5b5d5b0b59985a5b195960721b604082015260600190565b60208082526017908201527f76657269666965722d63592d6774652d7072696d652d71000000000000000000604082015260600190565b6020808252601f908201527f76657269666965722d6774652d736e61726b2d7363616c61722d6669656c6400604082015260600190565b60208082526018908201527f76657269666965722d6259302d6774652d7072696d652d710000000000000000604082015260600190565b60208082526017908201527f76657269666965722d61592d6774652d7072696d652d71000000000000000000604082015260600190565b6020808252601290820152711c185a5c9a5b99cb5859190b59985a5b195960721b604082015260600190565b60208082526017908201527f76657269666965722d63582d6774652d7072696d652d71000000000000000000604082015260600190565b6020808252601590820152741c185a5c9a5b99cb5bdc18dbd9194b59985a5b1959605a1b604082015260600190565b604051601f8201601f1916810167ffffffffffffffff8111828210171561112d5761112d6111f5565b604052919050565b600067ffffffffffffffff82111561114f5761114f6111f5565b5060200290565b60008219821115611169576111696111df565b500190565b6000816000190483118215151615611188576111886111df565b500290565b60008282101561119f5761119f6111df565b500390565b60006000198214156111b8576111b86111df565b5060010190565b6000826111da57634e487b7160e01b81526012600452602481fd5b500690565b634e487b7160e01b600052601160045260246000fd5b634e487b7160e01b600052604160045260246000fdfe30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47a26469706673582212205e4b7ca083f4c5fa95cc4f011bfe7cfe79546961c9d8dff74ff15168e578895f64736f6c63430008010033"

// DeployVerifier deploys a new Ethereum contract, binding an instance of Verifier to it.
func DeployVerifier(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Verifier, error) {
	parsed, err := abi.JSON(strings.NewReader(VerifierABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}

	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(VerifierBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Verifier{VerifierCaller: VerifierCaller{contract: contract}, VerifierTransactor: VerifierTransactor{contract: contract}, VerifierFilterer: VerifierFilterer{contract: contract}}, nil
}

// Verifier is an auto generated Go binding around an Ethereum contract.
type Verifier struct {
	VerifierCaller     // Read-only binding to the contract
	VerifierTransactor // Write-only binding to the contract
	VerifierFilterer   // Log filterer for contract events
}

// VerifierCaller is an auto generated read-only Go binding around an Ethereum contract.
type VerifierCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VerifierTransactor is an auto generated write-only Go binding around an Ethereum contract.
type VerifierTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VerifierFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type VerifierFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VerifierSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type VerifierSession struct {
	Contract     *Verifier         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// VerifierCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type VerifierCallerSession struct {
	Contract *VerifierCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// VerifierTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type VerifierTransactorSession struct {
	Contract     *VerifierTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// VerifierRaw is an auto generated low-level Go binding around an Ethereum contract.
type VerifierRaw struct {
	Contract *Verifier // Generic contract binding to access the raw methods on
}

// VerifierCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type VerifierCallerRaw struct {
	Contract *VerifierCaller // Generic read-only contract binding to access the raw methods on
}

// VerifierTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type VerifierTransactorRaw struct {
	Contract *VerifierTransactor // Generic write-only contract binding to access the raw methods on
}

// NewVerifier creates a new instance of Verifier, bound to a specific deployed contract.
func NewVerifier(address common.Address, backend bind.ContractBackend) (*Verifier, error) {
	contract, err := bindVerifier(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Verifier{VerifierCaller: VerifierCaller{contract: contract}, VerifierTransactor: VerifierTransactor{contract: contract}, VerifierFilterer: VerifierFilterer{contract: contract}}, nil
}

// NewVerifierCaller creates a new read-only instance of Verifier, bound to a specific deployed contract.
func NewVerifierCaller(address common.Address, caller bind.ContractCaller) (*VerifierCaller, error) {
	contract, err := bindVerifier(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &VerifierCaller{contract: contract}, nil
}

// NewVerifierTransactor creates a new write-only instance of Verifier, bound to a specific deployed contract.
func NewVerifierTransactor(address common.Address, transactor bind.ContractTransactor) (*VerifierTransactor, error) {
	contract, err := bindVerifier(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &VerifierTransactor{contract: contract}, nil
}

// NewVerifierFilterer creates a new log filterer instance of Verifier, bound to a specific deployed contract.
func NewVerifierFilterer(address common.Address, filterer bind.ContractFilterer) (*VerifierFilterer, error) {
	contract, err := bindVerifier(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &VerifierFilterer{contract: contract}, nil
}

// bindVerifier binds a generic wrapper to an already deployed contract.
func bindVerifier(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(VerifierABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Verifier *VerifierRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Verifier.Contract.VerifierCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Verifier *VerifierRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Verifier.Contract.VerifierTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Verifier *VerifierRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Verifier.Contract.VerifierTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Verifier *VerifierCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Verifier.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Verifier *VerifierTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Verifier.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Verifier *VerifierTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Verifier.Contract.contract.Transact(opts, method, params...)
}

// VerifyProof is a free data retrieval call binding the contract method 0x43753b4d.
//
// Solidity: function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[1] input) view returns(bool r)
func (_Verifier *VerifierCaller) VerifyProof(opts *bind.CallOpts, a [2]*big.Int, b [2][2]*big.Int, c [2]*big.Int, input [1]*big.Int) (bool, error) {
	var out []interface{}
	err := _Verifier.contract.Call(opts, &out, "verifyProof", a, b, c, input)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// VerifyProof is a free data retrieval call binding the contract method 0x43753b4d.
//
// Solidity: function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[1] input) view returns(bool r)
func (_Verifier *VerifierSession) VerifyProof(a [2]*big.Int, b [2][2]*big.Int, c [2]*big.Int, input [1]*big.Int) (bool, error) {
	return _Verifier.Contract.VerifyProof(&_Verifier.CallOpts, a, b, c, input)
}

// VerifyProof is a free data retrieval call binding the contract method 0x43753b4d.
//
// Solidity: function verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[1] input) view returns(bool r)
func (_Verifier *VerifierCallerSession) VerifyProof(a [2]*big.Int, b [2][2]*big.Int, c [2]*big.Int, input [1]*big.Int) (bool, error) {
	return _Verifier.Contract.VerifyProof(&_Verifier.CallOpts, a, b, c, input)
}
