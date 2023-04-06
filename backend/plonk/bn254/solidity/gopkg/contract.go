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
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"a\",\"type\":\"uint256\"}],\"name\":\"PrintUint256\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"uint256[]\",\"name\":\"inputs\",\"type\":\"uint256[]\"}],\"name\":\"test_batch_invert\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256[]\",\"name\":\"inputs\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"z\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"w\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"n\",\"type\":\"uint256\"}],\"name\":\"test_compute_sum_li_zi\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"res\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"i\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"z\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"w\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"n\",\"type\":\"uint256\"}],\"name\":\"test_eval_ith_lagrange\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"res\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"x\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"y\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"dst\",\"type\":\"string\"}],\"name\":\"test_hash\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"res\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Bin: "0x608060405234801561001057600080fd5b506119b1806100206000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c8063437a9c6a14610051578063c7baa21714610081578063d33410fd146100b1578063e0380a93146100cd575b600080fd5b61006b6004803603810190610066919061120d565b6100fd565b604051610078919061129f565b60405180910390f35b61009b6004803603810190610096919061136f565b61014c565b6040516100a8919061129f565b60405180910390f35b6100cb60048036038101906100c691906113de565b610199565b005b6100e760048036038101906100e29190611427565b61029f565b6040516100f4919061129f565b60405180910390f35b600061010b858585856102ee565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b8160405161013c919061129f565b60405180910390a1949350505050565b600061015984848461040a565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b8160405161018a919061129f565b60405180910390a19392505050565b60006101a482610570565b905060005b815181101561029a576101f08382815181106101c8576101c761148e565b5b60200260200101518383815181106101e3576101e261148e565b5b602002602001015161081f565b8282815181106102035761020261148e565b5b6020026020010181815250507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b8282815181106102435761024261148e565b5b6020026020010151604051610258919061129f565b60405180910390a160018282815181106102755761027461148e565b5b60200260200101511461028757600080fd5b8080610292906114ec565b9150506101a9565b505050565b60006102ad8585858561085b565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b816040516102de919061129f565b60405180910390a1949350505050565b6000806102fb8584610937565b90506000600190506000875190506000806000806103198b876109d0565b91506103268760016109d0565b90506103328183610a37565b925061033e838a610a37565b9250610365838d6000815181106103585761035761148e565b5b602002602001015161081f565b93506000600190505b858110156103f757610380848461081f565b935061038c848c61081f565b9350610398878c61081f565b96506103a48c886109d0565b92506103b08484610a37565b93506103d6848e83815181106103c9576103c861148e565b5b602002602001015161081f565b91506103e28286610a62565b945080806103ef906114ec565b91505061036e565b5083975050505050505050949350505050565b6000807f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000019050600061043d868686610a9e565b905060005b60208110156104a1578060086104589190611534565b8282602f6104669190611576565b603081106104775761047661148e565b5b602002015160ff16901b8461048c91906115aa565b93508080610499906114ec565b915050610442565b5081836104ae919061160d565b9250600080600090505b6010811015610517578060086104ce9190611534565b8382600f6104dc9190611576565b603081106104ed576104ec61148e565b5b602002015160ff16901b8261050291906115aa565b9150808061050f906114ec565b9150506104b8565b5060007f0e0a77c19a07df2f666ea36f7879462e36fc76959f60cd29ac96341c4ffffffb9050838061054c5761054b6115de565b5b818309915083806105605761055f6115de565b5b8286089450505050509392505050565b606060008251905060008167ffffffffffffffff81111561059457610593611094565b5b6040519080825280602002602001820160405280156105c25781602001602082028036833780820191505090505b509050836001836105d39190611576565b815181106105e4576105e361148e565b5b6020026020010151816001846105fa9190611576565b8151811061060b5761060a61148e565b5b60200260200101818152505060006001836106269190611576565b90505b60008111156106ba5761067c8282815181106106485761064761148e565b5b60200260200101518660018461065e9190611576565b8151811061066f5761066e61148e565b5b602002602001015161081f565b8260018361068a9190611576565b8151811061069b5761069a61148e565b5b60200260200101818152505080806106b29061163e565b915050610629565b5060006106ec826001856106ce9190611576565b815181106106df576106de61148e565b5b6020026020010151610e25565b905060008367ffffffffffffffff81111561070a57610709611094565b5b6040519080825280602002602001820160405280156107385781602001602082028036833780820191505090505b50905060006001905060005b8581101561081157610756848361081f565b8382815181106107695761076861148e565b5b6020026020010181815250508560018261078391906115aa565b146107fe576107b8848660018461079a91906115aa565b815181106107ab576107aa61148e565b5b602002602001015161081f565b8382815181106107cb576107ca61148e565b5b6020026020010181815250506107fb828983815181106107ee576107ed61148e565b5b602002602001015161081f565b91505b8080610809906114ec565b915050610744565b508195505050505050919050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001806108505761084f6115de565b5b828409905092915050565b600081851061086957600080fd5b7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001841061089557600080fd5b7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000183106108c157600080fd5b6108cb8386610937565b92506108d784846109d0565b94506108e38483610937565b93506108f08460016109d0565b93506108fb82610e25565b9150610907838361081f565b925061091285610e25565b945061091e838661081f565b925061092a838561081f565b9250829050949350505050565b6000806040518060c001604052806020815260200160208152602001602081526020018581526020018481526020017f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000018152509050610994611025565b600060208260c08560055afa9050806109ac57600080fd5b816000600181106109c0576109bf61148e565b5b6020020151935050505092915050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000180610a0157610a006115de565b5b827f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001610a2d9190611576565b8408905092915050565b6000808203610a4557600080fd5b610a4e82610e25565b9150610a5a838361081f565b905092915050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000180610a9357610a926115de565b5b828408905092915050565b610aa6611047565b6060600080603090506000610aba86610e70565b905060005b6040811015610aff578484604051602001610adb92919061171b565b60405160208183030381529060405294508080610af7906114ec565b915050610abf565b508388888585878b87604051602001610b1f9897969594939291906117ab565b60405160208183030381529060405293506000600285604051610b429190611835565b602060405180830381855afa158015610b5f573d6000803e3d6000fd5b5050506040513d601f19601f82011682018060405250810190610b829190611882565b90508060018884604051602001610b9c94939291906118d0565b60405160208183030381529060405294506000600286604051610bbf9190611835565b602060405180830381855afa158015610bdc573d6000803e3d6000fd5b5050506040513d601f19601f82011682018060405250810190610bff9190611882565b905060005b6020811015610c5e57818160208110610c2057610c1f61148e565b5b1a60f81b60f81c888260308110610c3a57610c3961148e565b5b602002019060ff16908160ff16815250508080610c56906114ec565b915050610c04565b5080600060208110610c7357610c7261148e565b5b1a60f81b60f81c82600060208110610c8e57610c8d61148e565b5b1a60f81b60f81c18604051602001610ca6919061191a565b60405160208183030381529060405295506000600190505b6020811015610d325786828260208110610cdb57610cda61148e565b5b1a60f81b60f81c848360208110610cf557610cf461148e565b5b1a60f81b60f81c18604051602001610d0e92919061171b565b60405160208183030381529060405296508080610d2a906114ec565b915050610cbe565b508560028985604051602001610d4b9493929190611935565b6040516020818303038152906040529550600286604051610d6c9190611835565b602060405180830381855afa158015610d89573d6000803e3d6000fd5b5050506040513d601f19601f82011682018060405250810190610dac9190611882565b905060005b6010811015610e1757818160208110610dcd57610dcc61148e565b5b1a60f81b60f81c88602083610de291906115aa565b60308110610df357610df261148e565b5b602002019060ff16908160ff16815250508080610e0f906114ec565b915050610db1565b505050505050509392505050565b6000808203610e3357600080fd5b610e698260027f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001610e649190611576565b610937565b9050919050565b60008060008084519050600092505b8082101561101a576000858381518110610e9c57610e9b61148e565b5b602001015160f81c60f81b9050608060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610eeb57600183610ee491906115aa565b9250611006565b60e060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610f2d57600283610f2691906115aa565b9250611005565b60f060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610f6f57600383610f6891906115aa565b9250611004565b60f8801b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610fb057600483610fa991906115aa565b9250611003565b60fc60f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610ff257600583610feb91906115aa565b9250611002565b600683610fff91906115aa565b92505b5b5b5b5b508280611012906114ec565b935050610e7f565b829350505050919050565b6040518060200160405280600190602082028036833780820191505090505090565b604051806106000160405280603090602082028036833780820191505090505090565b6000604051905090565b600080fd5b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6110cc82611083565b810181811067ffffffffffffffff821117156110eb576110ea611094565b5b80604052505050565b60006110fe61106a565b905061110a82826110c3565b919050565b600067ffffffffffffffff82111561112a57611129611094565b5b602082029050602081019050919050565b600080fd5b6000819050919050565b61115381611140565b811461115e57600080fd5b50565b6000813590506111708161114a565b92915050565b60006111896111848461110f565b6110f4565b905080838252602082019050602084028301858111156111ac576111ab61113b565b5b835b818110156111d557806111c18882611161565b8452602084019350506020810190506111ae565b5050509392505050565b600082601f8301126111f4576111f361107e565b5b8135611204848260208601611176565b91505092915050565b6000806000806080858703121561122757611226611074565b5b600085013567ffffffffffffffff81111561124557611244611079565b5b611251878288016111df565b945050602061126287828801611161565b935050604061127387828801611161565b925050606061128487828801611161565b91505092959194509250565b61129981611140565b82525050565b60006020820190506112b46000830184611290565b92915050565b600080fd5b600067ffffffffffffffff8211156112da576112d9611094565b5b6112e382611083565b9050602081019050919050565b82818337600083830152505050565b600061131261130d846112bf565b6110f4565b90508281526020810184848401111561132e5761132d6112ba565b5b6113398482856112f0565b509392505050565b600082601f8301126113565761135561107e565b5b81356113668482602086016112ff565b91505092915050565b60008060006060848603121561138857611387611074565b5b600061139686828701611161565b93505060206113a786828701611161565b925050604084013567ffffffffffffffff8111156113c8576113c7611079565b5b6113d486828701611341565b9150509250925092565b6000602082840312156113f4576113f3611074565b5b600082013567ffffffffffffffff81111561141257611411611079565b5b61141e848285016111df565b91505092915050565b6000806000806080858703121561144157611440611074565b5b600061144f87828801611161565b945050602061146087828801611161565b935050604061147187828801611161565b925050606061148287828801611161565b91505092959194509250565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006114f782611140565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203611529576115286114bd565b5b600182019050919050565b600061153f82611140565b915061154a83611140565b925082820261155881611140565b9150828204841483151761156f5761156e6114bd565b5b5092915050565b600061158182611140565b915061158c83611140565b92508282039050818111156115a4576115a36114bd565b5b92915050565b60006115b582611140565b91506115c083611140565b92508282019050808211156115d8576115d76114bd565b5b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b600061161882611140565b915061162383611140565b925082611633576116326115de565b5b828206905092915050565b600061164982611140565b91506000820361165c5761165b6114bd565b5b600182039050919050565b600081519050919050565b600081905092915050565b60005b8381101561169b578082015181840152602081019050611680565b60008484015250505050565b60006116b282611667565b6116bc8185611672565b93506116cc81856020860161167d565b80840191505092915050565b600060ff82169050919050565b60008160f81b9050919050565b60006116fd826116e5565b9050919050565b611715611710826116d8565b6116f2565b82525050565b600061172782856116a7565b91506117338284611704565b6001820191508190509392505050565b6000819050919050565b61175e61175982611140565b611743565b82525050565b600081519050919050565b600081905092915050565b600061178582611764565b61178f818561176f565b935061179f81856020860161167d565b80840191505092915050565b60006117b7828b6116a7565b91506117c3828a61174d565b6020820191506117d3828961174d565b6020820191506117e38288611704565b6001820191506117f38287611704565b6001820191506118038286611704565b600182019150611813828561177a565b915061181f8284611704565b6001820191508190509998505050505050505050565b600061184182846116a7565b915081905092915050565b6000819050919050565b61185f8161184c565b811461186a57600080fd5b50565b60008151905061187c81611856565b92915050565b60006020828403121561189857611897611074565b5b60006118a68482850161186d565b91505092915050565b6000819050919050565b6118ca6118c58261184c565b6118af565b82525050565b60006118dc82876118b9565b6020820191506118ec8286611704565b6001820191506118fc828561177a565b91506119088284611704565b60018201915081905095945050505050565b60006119268284611704565b60018201915081905092915050565b600061194182876116a7565b915061194d8286611704565b60018201915061195d828561177a565b91506119698284611704565b6001820191508190509594505050505056fea264697066735822122061cd89fb6d7ca625728312845f99b46aa6241180ad21b358f405442d42ae292164736f6c63430008130033",
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

// TestBatchInvert is a paid mutator transaction binding the contract method 0xd33410fd.
//
// Solidity: function test_batch_invert(uint256[] inputs) returns()
func (_Contract *ContractTransactor) TestBatchInvert(opts *bind.TransactOpts, inputs []*big.Int) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "test_batch_invert", inputs)
}

// TestBatchInvert is a paid mutator transaction binding the contract method 0xd33410fd.
//
// Solidity: function test_batch_invert(uint256[] inputs) returns()
func (_Contract *ContractSession) TestBatchInvert(inputs []*big.Int) (*types.Transaction, error) {
	return _Contract.Contract.TestBatchInvert(&_Contract.TransactOpts, inputs)
}

// TestBatchInvert is a paid mutator transaction binding the contract method 0xd33410fd.
//
// Solidity: function test_batch_invert(uint256[] inputs) returns()
func (_Contract *ContractTransactorSession) TestBatchInvert(inputs []*big.Int) (*types.Transaction, error) {
	return _Contract.Contract.TestBatchInvert(&_Contract.TransactOpts, inputs)
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
