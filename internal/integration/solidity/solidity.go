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
var PairingBin = "0x60566037600b82828239805160001a607314602a57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600080fdfea2646970667358221220aa815b0eaed5dfb0eb931be873a42e903cdba3e424c39b2dbbc3f80a8b4cbb5464736f6c63430008000033"

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
var VerifierBin = "0x608060405234801561001057600080fd5b50611293806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c806343753b4d14610030575b600080fd5b61004361003e366004610e0c565b610059565b6040516100509190610ebc565b60405180910390f35b6000610063610bcd565b6040805180820182528751815260208089015181830152908352815160808101835287515181840190815288518301516060830152815282518084018452888301805151825251830151818401528183015283820152815180830183528651815286820151918101919091529082015260006100dd6103dc565b60408051808201909152600080825260208201528351519192509060008051602061123e8339815191521161012d5760405162461bcd60e51b815260040161012490610efe565b60405180910390fd5b82516020015160008051602061123e8339815191521161015f5760405162461bcd60e51b815260040161012490611074565b6020830151515160008051602061123e833981519152116101925760405162461bcd60e51b815260040161012490610ec7565b60208381015101515160008051602061123e833981519152116101c75760405162461bcd60e51b81526004016101249061103d565b60208381015151015160008051602061123e833981519152116101fc5760405162461bcd60e51b815260040161012490610f6c565b602083810151810151015160008051602061123e833981519152116102335760405162461bcd60e51b815260040161012490610f35565b60408301515160008051602061123e833981519152116102655760405162461bcd60e51b8152600401610124906110d7565b60008051602061123e8339815191528360400151602001511061029a5760405162461bcd60e51b815260040161012490610fcf565b60005b6001811015610388577f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000018682600181106102e757634e487b7160e01b600052603260045260246000fd5b6020020151106103095760405162461bcd60e51b815260040161012490611006565b6103748261036f85608001518460016103229190611188565b6002811061034057634e487b7160e01b600052603260045260246000fd5b602002015189856001811061036557634e487b7160e01b600052603260045260246000fd5b60200201516106fc565b610767565b915080610380816111d6565b91505061029d565b5060808201515161039a908290610767565b90506103d06103ac84600001516107ce565b8460200151846000015185602001518587604001518960400151896060015161085b565b98975050505050505050565b6103e4610bff565b6040805180820182527f07efeb140fa20ff0ab48738de67bf2336a5e7edf61e447f05d647eb394b4c9bf81527f041b9b47e9483fd8f524f315b61691f19b14a4e92aa108eb09ceb3e2c7b96df96020808301919091529083528151608080820184527f05a7404dd4b79816b2b4aa22dd2044a63f3297555972f5b42b3590ab63d2e83e8285019081527f015fd76155a62b1d253bb85ebacc65798115df638081ed86b45cda57ec357de5606080850191909152908352845180860186527f0cea9a73f25066ece89bb2b9b224d6e3067d78b9929c5f943da7ad84a30e0a9c81527f0d8f947e071e7da12c44faf3936e726fd0e8e962f932a9bb92e914982920ac97818601528385015285840192909252835180820185527f26846ad6453c8ee56e027dec83f9534a820c542e0cdfeb05bb4161efbbc018c78186019081527f23cbc7019320000ff03d3b28dcd241278e07d97b90b56c565cf8c867429a75bd828501528152845180860186527efa7912977202658934746604ccab69fbaf99bbee85928f69393fb559c359d381527f18da1f1365a6bd8f44ee939cd5104b99ae112bed0f8cda9137237582e5897e7c818601528185015285850152835180820185527f0bea430bf2e0038ac7fde09de3217696675f37b435b50ef2e528cb651fdf9c8e8186019081527f28268c0d6dba8760e9061e7e6d713c18822545073c0f3994768bcbb9e4121bf7828501528152845180860186527f17fab16e4a8d5f0afb3ac70e950c8a40813b3ebec5e2807c7c60a004c1e6879281527f2423bd4fd5bf5d509e0ab616c7a764f58d8d585e50a61ce59f3646bd7aabdd6c818601528185015291850191909152825180840184527f1af7a5ec75b640728cb3ec9fd57ff256de6e1a6e79479038652820a45c61ff7a81527f1ad07114bace2cc1a5fcdac4ceebeb17f10689505c4f16789fc459f697c0ead78184015290840180519190915282518084019093527f2ee2739a0a0137827fb40828b29524cb5f183146e8a69b948ed3768bb75980b683527f2204b123cc427058ed21c083698ec786595d216a0014fcf4cf0d451c09956bee8383015251015290565b610704610c46565b61070c610c60565b835181526020808501519082015260408101839052600060608360808460076107d05a03fa905080801561073f57610741565bfe5b508061075f5760405162461bcd60e51b815260040161012490610fa3565b505092915050565b61076f610c46565b610777610c7e565b8351815260208085015181830152835160408301528301516060808301919091526000908360c08460066107d05a03fa905080801561073f57508061075f5760405162461bcd60e51b8152600401610124906110ab565b6107d6610c46565b81511580156107e757506020820151155b1561080657506040805180820190915260008082526020820152610856565b60405180604001604052808360000151815260200160008051602061123e833981519152846020015161083991906111f1565b6108519060008051602061123e8339815191526111bf565b905290505b919050565b60408051608080820183528a825260208083018a90528284018890526060808401879052845192830185528b83528282018a9052828501889052820185905283516018808252610320820190955260009491859190839082016103008036833701905050905060005b6004811015610b735760006108da8260066111a0565b90508582600481106108fc57634e487b7160e01b600052603260045260246000fd5b6020020151518361090e836000611188565b8151811061092c57634e487b7160e01b600052603260045260246000fd5b60200260200101818152505085826004811061095857634e487b7160e01b600052603260045260246000fd5b6020020151602001518382600161096f9190611188565b8151811061098d57634e487b7160e01b600052603260045260246000fd5b6020026020010181815250508482600481106109b957634e487b7160e01b600052603260045260246000fd5b60200201515151836109cc836002611188565b815181106109ea57634e487b7160e01b600052603260045260246000fd5b602002602001018181525050848260048110610a1657634e487b7160e01b600052603260045260246000fd5b6020020151516001602002015183610a2f836003611188565b81518110610a4d57634e487b7160e01b600052603260045260246000fd5b602002602001018181525050848260048110610a7957634e487b7160e01b600052603260045260246000fd5b602002015160200151600060028110610aa257634e487b7160e01b600052603260045260246000fd5b602002015183610ab3836004611188565b81518110610ad157634e487b7160e01b600052603260045260246000fd5b602002602001018181525050848260048110610afd57634e487b7160e01b600052603260045260246000fd5b602002015160200151600160028110610b2657634e487b7160e01b600052603260045260246000fd5b602002015183610b37836005611188565b81518110610b5557634e487b7160e01b600052603260045260246000fd5b60209081029190910101525080610b6b816111d6565b9150506108c4565b50610b7c610c9c565b6000602082602086026020860160086107d05a03fa905080801561073f575080610bb85760405162461bcd60e51b81526004016101249061110e565b505115159d9c50505050505050505050505050565b6040518060600160405280610be0610c46565b8152602001610bed610cba565b8152602001610bfa610c46565b905290565b6040518060a00160405280610c12610c46565b8152602001610c1f610cba565b8152602001610c2c610cba565b8152602001610c39610cba565b8152602001610bfa610cda565b604051806040016040528060008152602001600081525090565b60405180606001604052806003906020820280368337509192915050565b60405180608001604052806004906020820280368337509192915050565b60405180602001604052806001906020820280368337509192915050565b6040518060400160405280610ccd610d07565b8152602001610bfa610d07565b60405180604001604052806002905b610cf1610c46565b815260200190600190039081610ce95790505090565b60405180604001604052806002906020820280368337509192915050565b600082601f830112610d35578081fd5b604051602080820182811067ffffffffffffffff82111715610d5957610d59611227565b6040528184828101871015610d6c578485fd5b845b6001811015610d8b57813583529183019190830190600101610d6e565b50929695505050505050565b600082601f830112610da7578081fd5b6040516040810181811067ffffffffffffffff82111715610dca57610dca611227565b8060405250808385604086011115610de0578384fd5b835b6002811015610e01578135835260209283019290910190600101610de2565b509195945050505050565b6000806000806101208587031215610e22578384fd5b610e2c8686610d97565b9350604086605f870112610e3e578384fd5b6002610e51610e4c82611167565b61113d565b8083890160c08a018b811115610e65578889fd5b885b85811015610e8d57610e798d84610d97565b855260209094019391860191600101610e67565b50829850610e9b8c82610d97565b9750505050505050610eb1866101008701610d25565b905092959194509250565b901515815260200190565b60208082526018908201527f76657269666965722d6258302d6774652d7072696d652d710000000000000000604082015260600190565b60208082526017908201527f76657269666965722d61582d6774652d7072696d652d71000000000000000000604082015260600190565b60208082526018908201527f76657269666965722d6259312d6774652d7072696d652d710000000000000000604082015260600190565b60208082526018908201527f76657269666965722d6258312d6774652d7072696d652d710000000000000000604082015260600190565b6020808252601290820152711c185a5c9a5b99cb5b5d5b0b59985a5b195960721b604082015260600190565b60208082526017908201527f76657269666965722d63592d6774652d7072696d652d71000000000000000000604082015260600190565b6020808252601f908201527f76657269666965722d6774652d736e61726b2d7363616c61722d6669656c6400604082015260600190565b60208082526018908201527f76657269666965722d6259302d6774652d7072696d652d710000000000000000604082015260600190565b60208082526017908201527f76657269666965722d61592d6774652d7072696d652d71000000000000000000604082015260600190565b6020808252601290820152711c185a5c9a5b99cb5859190b59985a5b195960721b604082015260600190565b60208082526017908201527f76657269666965722d63582d6774652d7072696d652d71000000000000000000604082015260600190565b6020808252601590820152741c185a5c9a5b99cb5bdc18dbd9194b59985a5b1959605a1b604082015260600190565b60405181810167ffffffffffffffff8111828210171561115f5761115f611227565b604052919050565b600067ffffffffffffffff82111561118157611181611227565b5060200290565b6000821982111561119b5761119b611211565b500190565b60008160001904831182151516156111ba576111ba611211565b500290565b6000828210156111d1576111d1611211565b500390565b60006000198214156111ea576111ea611211565b5060010190565b60008261120c57634e487b7160e01b81526012600452602481fd5b500690565b634e487b7160e01b600052601160045260246000fd5b634e487b7160e01b600052604160045260246000fdfe30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47a2646970667358221220054b7b6a618674b795b4efcecb95d9d815dd112cefa19a6f0b6f492cd0db692464736f6c63430008000033"

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
