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
	Bin: "0x608060405234801561001057600080fd5b50611a32806100206000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c8063437a9c6a14610051578063c7baa21714610081578063d33410fd146100b1578063e0380a93146100cd575b600080fd5b61006b6004803603810190610066919061122e565b6100fd565b60405161007891906112c0565b60405180910390f35b61009b60048036038101906100969190611390565b61014c565b6040516100a891906112c0565b60405180910390f35b6100cb60048036038101906100c691906113ff565b610199565b005b6100e760048036038101906100e29190611448565b6102b1565b6040516100f491906112c0565b60405180910390f35b600061010b85858585610300565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b8160405161013c91906112c0565b60405180910390a1949350505050565b600061015984848461041c565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b8160405161018a91906112c0565b60405180910390a19392505050565b7fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b6130216040516101ca91906114f4565b60405180910390a160006101dd82610582565b905060005b81518110156102ac576102298382815181106102015761020061150f565b5b602002602001015183838151811061021c5761021b61150f565b5b6020026020010151610840565b82828151811061023c5761023b61150f565b5b6020026020010181815250507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b82828151811061027c5761027b61150f565b5b602002602001015160405161029191906112c0565b60405180910390a180806102a49061156d565b9150506101e2565b505050565b60006102bf8585858561087c565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b816040516102f091906112c0565b60405180910390a1949350505050565b60008061030d8584610958565b905060006001905060008751905060008060008061032b8b876109f1565b91506103388760016109f1565b90506103448183610a58565b9250610350838a610a58565b9250610377838d60008151811061036a5761036961150f565b5b6020026020010151610840565b93506000600190505b85811015610409576103928484610840565b935061039e848c610840565b93506103aa878c610840565b96506103b68c886109f1565b92506103c28484610a58565b93506103e8848e83815181106103db576103da61150f565b5b6020026020010151610840565b91506103f48286610a83565b945080806104019061156d565b915050610380565b5083975050505050505050949350505050565b6000807f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000019050600061044f868686610abf565b905060005b60208110156104b35780600861046a91906115b5565b8282602f61047891906115f7565b603081106104895761048861150f565b5b602002015160ff16901b8461049e919061162b565b935080806104ab9061156d565b915050610454565b5081836104c0919061168e565b9250600080600090505b6010811015610529578060086104e091906115b5565b8382600f6104ee91906115f7565b603081106104ff576104fe61150f565b5b602002015160ff16901b82610514919061162b565b915080806105219061156d565b9150506104ca565b5060007f0e0a77c19a07df2f666ea36f7879462e36fc76959f60cd29ac96341c4ffffffb9050838061055e5761055d61165f565b5b818309915083806105725761057161165f565b5b8286089450505050509392505050565b606060008251905060008167ffffffffffffffff8111156105a6576105a56110b5565b5b6040519080825280602002602001820160405280156105d45781602001602082028036833780820191505090505b509050836001836105e591906115f7565b815181106105f6576105f561150f565b5b60200260200101518160018461060c91906115f7565b8151811061061d5761061c61150f565b5b602002602001018181525050600060018361063891906115f7565b90505b60008111156106cc5761068e82828151811061065a5761065961150f565b5b60200260200101518660018461067091906115f7565b815181106106815761068061150f565b5b6020026020010151610840565b8260018361069c91906115f7565b815181106106ad576106ac61150f565b5b60200260200101818152505080806106c4906116bf565b91505061063b565b5060006106f3826000815181106106e6576106e561150f565b5b6020026020010151610e46565b905060008367ffffffffffffffff811115610711576107106110b5565b5b60405190808252806020026020018201604052801561073f5781602001602082028036833780820191505090505b50905060006001905060005b858110156108325761075d8483610840565b8382815181106107705761076f61150f565b5b6020026020010181815250508560018261078a919061162b565b1461081f576107d98382815181106107a5576107a461150f565b5b6020026020010151866001846107bb919061162b565b815181106107cc576107cb61150f565b5b6020026020010151610840565b8382815181106107ec576107eb61150f565b5b60200260200101818152505061081c8289838151811061080f5761080e61150f565b5b6020026020010151610840565b91505b808061082a9061156d565b91505061074b565b508195505050505050919050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001806108715761087061165f565b5b828409905092915050565b600081851061088a57600080fd5b7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000184106108b657600080fd5b7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000183106108e257600080fd5b6108ec8386610958565b92506108f884846109f1565b94506109048483610958565b93506109118460016109f1565b935061091c82610e46565b91506109288383610840565b925061093385610e46565b945061093f8386610840565b925061094b8385610840565b9250829050949350505050565b6000806040518060c001604052806020815260200160208152602001602081526020018581526020018481526020017f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000181525090506109b5611046565b600060208260c08560055afa9050806109cd57600080fd5b816000600181106109e1576109e061150f565b5b6020020151935050505092915050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000180610a2257610a2161165f565b5b827f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001610a4e91906115f7565b8408905092915050565b6000808203610a6657600080fd5b610a6f82610e46565b9150610a7b8383610840565b905092915050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000180610ab457610ab361165f565b5b828408905092915050565b610ac7611068565b6060600080603090506000610adb86610e91565b905060005b6040811015610b20578484604051602001610afc92919061179c565b60405160208183030381529060405294508080610b189061156d565b915050610ae0565b508388888585878b87604051602001610b4098979695949392919061182c565b60405160208183030381529060405293506000600285604051610b6391906118b6565b602060405180830381855afa158015610b80573d6000803e3d6000fd5b5050506040513d601f19601f82011682018060405250810190610ba39190611903565b90508060018884604051602001610bbd9493929190611951565b60405160208183030381529060405294506000600286604051610be091906118b6565b602060405180830381855afa158015610bfd573d6000803e3d6000fd5b5050506040513d601f19601f82011682018060405250810190610c209190611903565b905060005b6020811015610c7f57818160208110610c4157610c4061150f565b5b1a60f81b60f81c888260308110610c5b57610c5a61150f565b5b602002019060ff16908160ff16815250508080610c779061156d565b915050610c25565b5080600060208110610c9457610c9361150f565b5b1a60f81b60f81c82600060208110610caf57610cae61150f565b5b1a60f81b60f81c18604051602001610cc7919061199b565b60405160208183030381529060405295506000600190505b6020811015610d535786828260208110610cfc57610cfb61150f565b5b1a60f81b60f81c848360208110610d1657610d1561150f565b5b1a60f81b60f81c18604051602001610d2f92919061179c565b60405160208183030381529060405296508080610d4b9061156d565b915050610cdf565b508560028985604051602001610d6c94939291906119b6565b6040516020818303038152906040529550600286604051610d8d91906118b6565b602060405180830381855afa158015610daa573d6000803e3d6000fd5b5050506040513d601f19601f82011682018060405250810190610dcd9190611903565b905060005b6010811015610e3857818160208110610dee57610ded61150f565b5b1a60f81b60f81c88602083610e03919061162b565b60308110610e1457610e1361150f565b5b602002019060ff16908160ff16815250508080610e309061156d565b915050610dd2565b505050505050509392505050565b6000808203610e5457600080fd5b610e8a8260027f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001610e8591906115f7565b610958565b9050919050565b60008060008084519050600092505b8082101561103b576000858381518110610ebd57610ebc61150f565b5b602001015160f81c60f81b9050608060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610f0c57600183610f05919061162b565b9250611027565b60e060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610f4e57600283610f47919061162b565b9250611026565b60f060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610f9057600383610f89919061162b565b9250611025565b60f8801b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610fd157600483610fca919061162b565b9250611024565b60fc60f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191610156110135760058361100c919061162b565b9250611023565b600683611020919061162b565b92505b5b5b5b5b5082806110339061156d565b935050610ea0565b829350505050919050565b6040518060200160405280600190602082028036833780820191505090505090565b604051806106000160405280603090602082028036833780820191505090505090565b6000604051905090565b600080fd5b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6110ed826110a4565b810181811067ffffffffffffffff8211171561110c5761110b6110b5565b5b80604052505050565b600061111f61108b565b905061112b82826110e4565b919050565b600067ffffffffffffffff82111561114b5761114a6110b5565b5b602082029050602081019050919050565b600080fd5b6000819050919050565b61117481611161565b811461117f57600080fd5b50565b6000813590506111918161116b565b92915050565b60006111aa6111a584611130565b611115565b905080838252602082019050602084028301858111156111cd576111cc61115c565b5b835b818110156111f657806111e28882611182565b8452602084019350506020810190506111cf565b5050509392505050565b600082601f8301126112155761121461109f565b5b8135611225848260208601611197565b91505092915050565b6000806000806080858703121561124857611247611095565b5b600085013567ffffffffffffffff8111156112665761126561109a565b5b61127287828801611200565b945050602061128387828801611182565b935050604061129487828801611182565b92505060606112a587828801611182565b91505092959194509250565b6112ba81611161565b82525050565b60006020820190506112d560008301846112b1565b92915050565b600080fd5b600067ffffffffffffffff8211156112fb576112fa6110b5565b5b611304826110a4565b9050602081019050919050565b82818337600083830152505050565b600061133361132e846112e0565b611115565b90508281526020810184848401111561134f5761134e6112db565b5b61135a848285611311565b509392505050565b600082601f8301126113775761137661109f565b5b8135611387848260208601611320565b91505092915050565b6000806000606084860312156113a9576113a8611095565b5b60006113b786828701611182565b93505060206113c886828701611182565b925050604084013567ffffffffffffffff8111156113e9576113e861109a565b5b6113f586828701611362565b9150509250925092565b60006020828403121561141557611414611095565b5b600082013567ffffffffffffffff8111156114335761143261109a565b5b61143f84828501611200565b91505092915050565b6000806000806080858703121561146257611461611095565b5b600061147087828801611182565b945050602061148187828801611182565b935050604061149287828801611182565b92505060606114a387828801611182565b91505092959194509250565b6000819050919050565b6000819050919050565b60006114de6114d96114d4846114af565b6114b9565b611161565b9050919050565b6114ee816114c3565b82525050565b600060208201905061150960008301846114e5565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061157882611161565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036115aa576115a961153e565b5b600182019050919050565b60006115c082611161565b91506115cb83611161565b92508282026115d981611161565b915082820484148315176115f0576115ef61153e565b5b5092915050565b600061160282611161565b915061160d83611161565b92508282039050818111156116255761162461153e565b5b92915050565b600061163682611161565b915061164183611161565b92508282019050808211156116595761165861153e565b5b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b600061169982611161565b91506116a483611161565b9250826116b4576116b361165f565b5b828206905092915050565b60006116ca82611161565b9150600082036116dd576116dc61153e565b5b600182039050919050565b600081519050919050565b600081905092915050565b60005b8381101561171c578082015181840152602081019050611701565b60008484015250505050565b6000611733826116e8565b61173d81856116f3565b935061174d8185602086016116fe565b80840191505092915050565b600060ff82169050919050565b60008160f81b9050919050565b600061177e82611766565b9050919050565b61179661179182611759565b611773565b82525050565b60006117a88285611728565b91506117b48284611785565b6001820191508190509392505050565b6000819050919050565b6117df6117da82611161565b6117c4565b82525050565b600081519050919050565b600081905092915050565b6000611806826117e5565b61181081856117f0565b93506118208185602086016116fe565b80840191505092915050565b6000611838828b611728565b9150611844828a6117ce565b60208201915061185482896117ce565b6020820191506118648288611785565b6001820191506118748287611785565b6001820191506118848286611785565b60018201915061189482856117fb565b91506118a08284611785565b6001820191508190509998505050505050505050565b60006118c28284611728565b915081905092915050565b6000819050919050565b6118e0816118cd565b81146118eb57600080fd5b50565b6000815190506118fd816118d7565b92915050565b60006020828403121561191957611918611095565b5b6000611927848285016118ee565b91505092915050565b6000819050919050565b61194b611946826118cd565b611930565b82525050565b600061195d828761193a565b60208201915061196d8286611785565b60018201915061197d82856117fb565b91506119898284611785565b60018201915081905095945050505050565b60006119a78284611785565b60018201915081905092915050565b60006119c28287611728565b91506119ce8286611785565b6001820191506119de82856117fb565b91506119ea8284611785565b6001820191508190509594505050505056fea264697066735822122031986b5015d9577293dcb53572dde643d0a9a8ec62b51b82965569b5421711b164736f6c63430008130033",
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
