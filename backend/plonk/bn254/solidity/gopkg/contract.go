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
	Bin: "0x608060405234801561001057600080fd5b50611a58806100206000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c8063437a9c6a14610051578063c7baa21714610081578063d33410fd146100b1578063e0380a93146100cd575b600080fd5b61006b60048036038101906100669190611254565b6100fd565b60405161007891906112e6565b60405180910390f35b61009b600480360381019061009691906113b6565b61014c565b6040516100a891906112e6565b60405180910390f35b6100cb60048036038101906100c69190611425565b610199565b005b6100e760048036038101906100e2919061146e565b6102e6565b6040516100f491906112e6565b60405180910390f35b600061010b85858585610335565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b8160405161013c91906112e6565b60405180910390a1949350505050565b6000610159848484610451565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b8160405161018a91906112e6565b60405180910390a19392505050565b60016000146101a757600080fd5b7fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b6130216040516101d8919061151a565b60405180910390a160006101eb826105b7565b905060005b81518110156102e15761023783828151811061020f5761020e611535565b5b602002602001015183838151811061022a57610229611535565b5b6020026020010151610866565b82828151811061024a57610249611535565b5b6020026020010181815250507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b82828151811061028a57610289611535565b5b602002602001015160405161029f91906112e6565b60405180910390a160018282815181106102bc576102bb611535565b5b6020026020010151146102ce57600080fd5b80806102d990611593565b9150506101f0565b505050565b60006102f4858585856108a2565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b8160405161032591906112e6565b60405180910390a1949350505050565b600080610342858461097e565b90506000600190506000875190506000806000806103608b87610a17565b915061036d876001610a17565b90506103798183610a7e565b9250610385838a610a7e565b92506103ac838d60008151811061039f5761039e611535565b5b6020026020010151610866565b93506000600190505b8581101561043e576103c78484610866565b93506103d3848c610866565b93506103df878c610866565b96506103eb8c88610a17565b92506103f78484610a7e565b935061041d848e83815181106104105761040f611535565b5b6020026020010151610866565b91506104298286610aa9565b9450808061043690611593565b9150506103b5565b5083975050505050505050949350505050565b6000807f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000190506000610484868686610ae5565b905060005b60208110156104e85780600861049f91906115db565b8282602f6104ad919061161d565b603081106104be576104bd611535565b5b602002015160ff16901b846104d39190611651565b935080806104e090611593565b915050610489565b5081836104f591906116b4565b9250600080600090505b601081101561055e5780600861051591906115db565b8382600f610523919061161d565b6030811061053457610533611535565b5b602002015160ff16901b826105499190611651565b9150808061055690611593565b9150506104ff565b5060007f0e0a77c19a07df2f666ea36f7879462e36fc76959f60cd29ac96341c4ffffffb9050838061059357610592611685565b5b818309915083806105a7576105a6611685565b5b8286089450505050509392505050565b606060008251905060008167ffffffffffffffff8111156105db576105da6110db565b5b6040519080825280602002602001820160405280156106095781602001602082028036833780820191505090505b5090508360018361061a919061161d565b8151811061062b5761062a611535565b5b602002602001015181600184610641919061161d565b8151811061065257610651611535565b5b602002602001018181525050600060018361066d919061161d565b90505b6000811115610701576106c382828151811061068f5761068e611535565b5b6020026020010151866001846106a5919061161d565b815181106106b6576106b5611535565b5b6020026020010151610866565b826001836106d1919061161d565b815181106106e2576106e1611535565b5b60200260200101818152505080806106f9906116e5565b915050610670565b50600061073382600185610715919061161d565b8151811061072657610725611535565b5b6020026020010151610e6c565b905060008367ffffffffffffffff811115610751576107506110db565b5b60405190808252806020026020018201604052801561077f5781602001602082028036833780820191505090505b50905060006001905060005b858110156108585761079d8483610866565b8382815181106107b0576107af611535565b5b602002602001018181525050856001826107ca9190611651565b14610845576107ff84866001846107e19190611651565b815181106107f2576107f1611535565b5b6020026020010151610866565b83828151811061081257610811611535565b5b6020026020010181815250506108428289838151811061083557610834611535565b5b6020026020010151610866565b91505b808061085090611593565b91505061078b565b508195505050505050919050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000018061089757610896611685565b5b828409905092915050565b60008185106108b057600080fd5b7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000184106108dc57600080fd5b7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001831061090857600080fd5b610912838661097e565b925061091e8484610a17565b945061092a848361097e565b9350610937846001610a17565b935061094282610e6c565b915061094e8383610866565b925061095985610e6c565b94506109658386610866565b92506109718385610866565b9250829050949350505050565b6000806040518060c001604052806020815260200160208152602001602081526020018581526020018481526020017f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000181525090506109db61106c565b600060208260c08560055afa9050806109f357600080fd5b81600060018110610a0757610a06611535565b5b6020020151935050505092915050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000180610a4857610a47611685565b5b827f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001610a74919061161d565b8408905092915050565b6000808203610a8c57600080fd5b610a9582610e6c565b9150610aa18383610866565b905092915050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000180610ada57610ad9611685565b5b828408905092915050565b610aed61108e565b6060600080603090506000610b0186610eb7565b905060005b6040811015610b46578484604051602001610b229291906117c2565b60405160208183030381529060405294508080610b3e90611593565b915050610b06565b508388888585878b87604051602001610b66989796959493929190611852565b60405160208183030381529060405293506000600285604051610b8991906118dc565b602060405180830381855afa158015610ba6573d6000803e3d6000fd5b5050506040513d601f19601f82011682018060405250810190610bc99190611929565b90508060018884604051602001610be39493929190611977565b60405160208183030381529060405294506000600286604051610c0691906118dc565b602060405180830381855afa158015610c23573d6000803e3d6000fd5b5050506040513d601f19601f82011682018060405250810190610c469190611929565b905060005b6020811015610ca557818160208110610c6757610c66611535565b5b1a60f81b60f81c888260308110610c8157610c80611535565b5b602002019060ff16908160ff16815250508080610c9d90611593565b915050610c4b565b5080600060208110610cba57610cb9611535565b5b1a60f81b60f81c82600060208110610cd557610cd4611535565b5b1a60f81b60f81c18604051602001610ced91906119c1565b60405160208183030381529060405295506000600190505b6020811015610d795786828260208110610d2257610d21611535565b5b1a60f81b60f81c848360208110610d3c57610d3b611535565b5b1a60f81b60f81c18604051602001610d559291906117c2565b60405160208183030381529060405296508080610d7190611593565b915050610d05565b508560028985604051602001610d9294939291906119dc565b6040516020818303038152906040529550600286604051610db391906118dc565b602060405180830381855afa158015610dd0573d6000803e3d6000fd5b5050506040513d601f19601f82011682018060405250810190610df39190611929565b905060005b6010811015610e5e57818160208110610e1457610e13611535565b5b1a60f81b60f81c88602083610e299190611651565b60308110610e3a57610e39611535565b5b602002019060ff16908160ff16815250508080610e5690611593565b915050610df8565b505050505050509392505050565b6000808203610e7a57600080fd5b610eb08260027f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001610eab919061161d565b61097e565b9050919050565b60008060008084519050600092505b80821015611061576000858381518110610ee357610ee2611535565b5b602001015160f81c60f81b9050608060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610f3257600183610f2b9190611651565b925061104d565b60e060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610f7457600283610f6d9190611651565b925061104c565b60f060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610fb657600383610faf9190611651565b925061104b565b60f8801b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015610ff757600483610ff09190611651565b925061104a565b60fc60f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015611039576005836110329190611651565b9250611049565b6006836110469190611651565b92505b5b5b5b5b50828061105990611593565b935050610ec6565b829350505050919050565b6040518060200160405280600190602082028036833780820191505090505090565b604051806106000160405280603090602082028036833780820191505090505090565b6000604051905090565b600080fd5b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b611113826110ca565b810181811067ffffffffffffffff82111715611132576111316110db565b5b80604052505050565b60006111456110b1565b9050611151828261110a565b919050565b600067ffffffffffffffff821115611171576111706110db565b5b602082029050602081019050919050565b600080fd5b6000819050919050565b61119a81611187565b81146111a557600080fd5b50565b6000813590506111b781611191565b92915050565b60006111d06111cb84611156565b61113b565b905080838252602082019050602084028301858111156111f3576111f2611182565b5b835b8181101561121c578061120888826111a8565b8452602084019350506020810190506111f5565b5050509392505050565b600082601f83011261123b5761123a6110c5565b5b813561124b8482602086016111bd565b91505092915050565b6000806000806080858703121561126e5761126d6110bb565b5b600085013567ffffffffffffffff81111561128c5761128b6110c0565b5b61129887828801611226565b94505060206112a9878288016111a8565b93505060406112ba878288016111a8565b92505060606112cb878288016111a8565b91505092959194509250565b6112e081611187565b82525050565b60006020820190506112fb60008301846112d7565b92915050565b600080fd5b600067ffffffffffffffff821115611321576113206110db565b5b61132a826110ca565b9050602081019050919050565b82818337600083830152505050565b600061135961135484611306565b61113b565b90508281526020810184848401111561137557611374611301565b5b611380848285611337565b509392505050565b600082601f83011261139d5761139c6110c5565b5b81356113ad848260208601611346565b91505092915050565b6000806000606084860312156113cf576113ce6110bb565b5b60006113dd868287016111a8565b93505060206113ee868287016111a8565b925050604084013567ffffffffffffffff81111561140f5761140e6110c0565b5b61141b86828701611388565b9150509250925092565b60006020828403121561143b5761143a6110bb565b5b600082013567ffffffffffffffff811115611459576114586110c0565b5b61146584828501611226565b91505092915050565b60008060008060808587031215611488576114876110bb565b5b6000611496878288016111a8565b94505060206114a7878288016111a8565b93505060406114b8878288016111a8565b92505060606114c9878288016111a8565b91505092959194509250565b6000819050919050565b6000819050919050565b60006115046114ff6114fa846114d5565b6114df565b611187565b9050919050565b611514816114e9565b82525050565b600060208201905061152f600083018461150b565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061159e82611187565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036115d0576115cf611564565b5b600182019050919050565b60006115e682611187565b91506115f183611187565b92508282026115ff81611187565b9150828204841483151761161657611615611564565b5b5092915050565b600061162882611187565b915061163383611187565b925082820390508181111561164b5761164a611564565b5b92915050565b600061165c82611187565b915061166783611187565b925082820190508082111561167f5761167e611564565b5b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b60006116bf82611187565b91506116ca83611187565b9250826116da576116d9611685565b5b828206905092915050565b60006116f082611187565b91506000820361170357611702611564565b5b600182039050919050565b600081519050919050565b600081905092915050565b60005b83811015611742578082015181840152602081019050611727565b60008484015250505050565b60006117598261170e565b6117638185611719565b9350611773818560208601611724565b80840191505092915050565b600060ff82169050919050565b60008160f81b9050919050565b60006117a48261178c565b9050919050565b6117bc6117b78261177f565b611799565b82525050565b60006117ce828561174e565b91506117da82846117ab565b6001820191508190509392505050565b6000819050919050565b61180561180082611187565b6117ea565b82525050565b600081519050919050565b600081905092915050565b600061182c8261180b565b6118368185611816565b9350611846818560208601611724565b80840191505092915050565b600061185e828b61174e565b915061186a828a6117f4565b60208201915061187a82896117f4565b60208201915061188a82886117ab565b60018201915061189a82876117ab565b6001820191506118aa82866117ab565b6001820191506118ba8285611821565b91506118c682846117ab565b6001820191508190509998505050505050505050565b60006118e8828461174e565b915081905092915050565b6000819050919050565b611906816118f3565b811461191157600080fd5b50565b600081519050611923816118fd565b92915050565b60006020828403121561193f5761193e6110bb565b5b600061194d84828501611914565b91505092915050565b6000819050919050565b61197161196c826118f3565b611956565b82525050565b60006119838287611960565b60208201915061199382866117ab565b6001820191506119a38285611821565b91506119af82846117ab565b60018201915081905095945050505050565b60006119cd82846117ab565b60018201915081905092915050565b60006119e8828761174e565b91506119f482866117ab565b600182019150611a048285611821565b9150611a1082846117ab565b6001820191508190509594505050505056fea2646970667358221220d84e3600563a1319934d768ee7ec5468b30901bce147a4d03a9b4f275cf6873564736f6c63430008130033",
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
