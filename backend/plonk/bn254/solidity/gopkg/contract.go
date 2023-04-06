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
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"a\",\"type\":\"uint256\"}],\"name\":\"PrintUint256\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"k\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"z\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"w\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"n\",\"type\":\"uint256\"}],\"name\":\"test_batch_compute_lagrange\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256[]\",\"name\":\"inputs\",\"type\":\"uint256[]\"}],\"name\":\"test_batch_invert\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256[]\",\"name\":\"inputs\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"z\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"w\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"n\",\"type\":\"uint256\"}],\"name\":\"test_compute_sum_li_zi\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"res\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"i\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"z\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"w\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"n\",\"type\":\"uint256\"}],\"name\":\"test_eval_ith_lagrange\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"res\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"x\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"y\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"dst\",\"type\":\"string\"}],\"name\":\"test_hash\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"res\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Bin: "0x608060405234801561001057600080fd5b50611fd2806100206000396000f3fe608060405234801561001057600080fd5b50600436106100575760003560e01c806332bc469a1461005c578063437a9c6a14610078578063c7baa217146100a8578063d33410fd146100d8578063e0380a93146100f4575b600080fd5b610076600480360381019061007191906115c9565b610124565b005b610092600480360381019061008d9190611789565b610238565b60405161009f919061181b565b60405180910390f35b6100c260048036038101906100bd91906118eb565b610287565b6040516100cf919061181b565b60405180910390f35b6100f260048036038101906100ed919061195a565b6102d4565b005b61010e600480360381019061010991906115c9565b6103ec565b60405161011b919061181b565b60405180910390f35b7fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b620f462960405161015691906119e8565b60405180910390a1600061016c8585858561043b565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b61350b60405161019f9190611a3e565b60405180910390a160005b858110156102305760006101c0828787876107f4565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b6102078484815181106101f9576101f8611a59565b5b6020026020010151836108d0565b604051610214919061181b565b60405180910390a150808061022890611ab7565b9150506101aa565b505050505050565b600061024685858585610937565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b81604051610277919061181b565b60405180910390a1949350505050565b6000610294848484610a53565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b816040516102c5919061181b565b60405180910390a19392505050565b7fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b6130216040516103059190611b3a565b60405180910390a1600061031882610bb9565b905060005b81518110156103e75761036483828151811061033c5761033b611a59565b5b602002602001015183838151811061035757610356611a59565b5b6020026020010151610e77565b82828151811061037757610376611a59565b5b6020026020010181815250507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b8282815181106103b7576103b6611a59565b5b60200260200101516040516103cc919061181b565b60405180910390a180806103df90611ab7565b91505061031d565b505050565b60006103fa858585856107f4565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b8160405161042b919061181b565b60405180910390a1949350505050565b606060008567ffffffffffffffff81111561045957610458611646565b5b6040519080825280602002602001820160405280156104875781602001602082028036833780820191505090505b50905060006001905060005b878110156104f7576104a587836108d0565b8382815181106104b8576104b7611a59565b5b602002602001018181525050876001826104d29190611b55565b146104e4576104e18287610e77565b91505b80806104ef90611ab7565b915050610493565b5061051d8260008151811061050f5761050e611a59565b5b602002602001015185610e77565b8260008151811061053157610530611a59565b5b6020026020010181815250507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b8260008151811061057257610571611a59565b5b6020026020010151604051610587919061181b565b60405180910390a1600061059a83610bb9565b90507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b816000815181106105d1576105d0611a59565b5b60200260200101516040516105e6919061181b565b60405180910390a16105f88786610eb3565b91506106058260016108d0565b91507fc06f90efa9c91dc43be8c00f432325e29d17851ab0f40844b418121428cc043b82604051610636919061181b565b60405180910390a1610663828260008151811061065657610655611a59565b5b6020026020010151610e77565b8160008151811061067757610676611a59565b5b60200260200101818152505061068e8760016108d0565b836000815181106106a2576106a1611a59565b5b6020026020010181815250506000600190505b888110156107e5576107078282815181106106d3576106d2611a59565b5b6020026020010151856001846106e99190611b89565b815181106106fa576106f9611a59565b5b6020026020010151610e77565b82828151811061071a57610719611a59565b5b60200260200101818152505061074a82828151811061073c5761073b611a59565b5b602002602001015188610e77565b82828151811061075d5761075c611a59565b5b6020026020010181815250506107b382828151811061077f5761077e611a59565b5b6020026020010151836001846107959190611b89565b815181106107a6576107a5611a59565b5b6020026020010151610e77565b8282815181106107c6576107c5611a59565b5b60200260200101818152505080806107dd90611ab7565b9150506106b5565b50809350505050949350505050565b600081851061080257600080fd5b7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001841061082e57600080fd5b7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001831061085a57600080fd5b6108648386610eb3565b925061087084846108d0565b945061087c8483610eb3565b93506108898460016108d0565b935061089482610f4c565b91506108a08383610e77565b92506108ab85610f4c565b94506108b78386610e77565b92506108c38385610e77565b9250829050949350505050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000018061090157610900611bbd565b5b827f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000161092d9190611b89565b8408905092915050565b6000806109448584610eb3565b90506000600190506000875190506000806000806109628b876108d0565b915061096f8760016108d0565b905061097b8183610f97565b9250610987838a610f97565b92506109ae838d6000815181106109a1576109a0611a59565b5b6020026020010151610e77565b93506000600190505b85811015610a40576109c98484610e77565b93506109d5848c610e77565b93506109e1878c610e77565b96506109ed8c886108d0565b92506109f98484610f97565b9350610a1f848e8381518110610a1257610a11611a59565b5b6020026020010151610e77565b9150610a2b8286610fc2565b94508080610a3890611ab7565b9150506109b7565b5083975050505050505050949350505050565b6000807f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000190506000610a86868686610ffe565b905060005b6020811015610aea57806008610aa19190611bec565b8282602f610aaf9190611b89565b60308110610ac057610abf611a59565b5b602002015160ff16901b84610ad59190611b55565b93508080610ae290611ab7565b915050610a8b565b508183610af79190611c2e565b9250600080600090505b6010811015610b6057806008610b179190611bec565b8382600f610b259190611b89565b60308110610b3657610b35611a59565b5b602002015160ff16901b82610b4b9190611b55565b91508080610b5890611ab7565b915050610b01565b5060007f0e0a77c19a07df2f666ea36f7879462e36fc76959f60cd29ac96341c4ffffffb90508380610b9557610b94611bbd565b5b81830991508380610ba957610ba8611bbd565b5b8286089450505050509392505050565b606060008251905060008167ffffffffffffffff811115610bdd57610bdc611646565b5b604051908082528060200260200182016040528015610c0b5781602001602082028036833780820191505090505b50905083600183610c1c9190611b89565b81518110610c2d57610c2c611a59565b5b602002602001015181600184610c439190611b89565b81518110610c5457610c53611a59565b5b6020026020010181815250506000600183610c6f9190611b89565b90505b6000811115610d0357610cc5828281518110610c9157610c90611a59565b5b602002602001015186600184610ca79190611b89565b81518110610cb857610cb7611a59565b5b6020026020010151610e77565b82600183610cd39190611b89565b81518110610ce457610ce3611a59565b5b6020026020010181815250508080610cfb90611c5f565b915050610c72565b506000610d2a82600081518110610d1d57610d1c611a59565b5b6020026020010151610f4c565b905060008367ffffffffffffffff811115610d4857610d47611646565b5b604051908082528060200260200182016040528015610d765781602001602082028036833780820191505090505b50905060006001905060005b85811015610e6957610d948483610e77565b838281518110610da757610da6611a59565b5b60200260200101818152505085600182610dc19190611b55565b14610e5657610e10838281518110610ddc57610ddb611a59565b5b602002602001015186600184610df29190611b55565b81518110610e0357610e02611a59565b5b6020026020010151610e77565b838281518110610e2357610e22611a59565b5b602002602001018181525050610e5382898381518110610e4657610e45611a59565b5b6020026020010151610e77565b91505b8080610e6190611ab7565b915050610d82565b508195505050505050919050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000180610ea857610ea7611bbd565b5b828409905092915050565b6000806040518060c001604052806020815260200160208152602001602081526020018581526020018481526020017f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000018152509050610f1061153a565b600060208260c08560055afa905080610f2857600080fd5b81600060018110610f3c57610f3b611a59565b5b6020020151935050505092915050565b6000808203610f5a57600080fd5b610f908260027f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001610f8b9190611b89565b610eb3565b9050919050565b6000808203610fa557600080fd5b610fae82610f4c565b9150610fba8383610e77565b905092915050565b60007f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000180610ff357610ff2611bbd565b5b828408905092915050565b61100661155c565b606060008060309050600061101a86611385565b905060005b604081101561105f57848460405160200161103b929190611d3c565b6040516020818303038152906040529450808061105790611ab7565b91505061101f565b508388888585878b8760405160200161107f989796959493929190611dcc565b604051602081830303815290604052935060006002856040516110a29190611e56565b602060405180830381855afa1580156110bf573d6000803e3d6000fd5b5050506040513d601f19601f820116820180604052508101906110e29190611ea3565b905080600188846040516020016110fc9493929190611ef1565b6040516020818303038152906040529450600060028660405161111f9190611e56565b602060405180830381855afa15801561113c573d6000803e3d6000fd5b5050506040513d601f19601f8201168201806040525081019061115f9190611ea3565b905060005b60208110156111be578181602081106111805761117f611a59565b5b1a60f81b60f81c88826030811061119a57611199611a59565b5b602002019060ff16908160ff168152505080806111b690611ab7565b915050611164565b50806000602081106111d3576111d2611a59565b5b1a60f81b60f81c826000602081106111ee576111ed611a59565b5b1a60f81b60f81c186040516020016112069190611f3b565b60405160208183030381529060405295506000600190505b6020811015611292578682826020811061123b5761123a611a59565b5b1a60f81b60f81c84836020811061125557611254611a59565b5b1a60f81b60f81c1860405160200161126e929190611d3c565b6040516020818303038152906040529650808061128a90611ab7565b91505061121e565b5085600289856040516020016112ab9493929190611f56565b60405160208183030381529060405295506002866040516112cc9190611e56565b602060405180830381855afa1580156112e9573d6000803e3d6000fd5b5050506040513d601f19601f8201168201806040525081019061130c9190611ea3565b905060005b60108110156113775781816020811061132d5761132c611a59565b5b1a60f81b60f81c886020836113429190611b55565b6030811061135357611352611a59565b5b602002019060ff16908160ff1681525050808061136f90611ab7565b915050611311565b505050505050509392505050565b60008060008084519050600092505b8082101561152f5760008583815181106113b1576113b0611a59565b5b602001015160f81c60f81b9050608060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015611400576001836113f99190611b55565b925061151b565b60e060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191610156114425760028361143b9190611b55565b925061151a565b60f060f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191610156114845760038361147d9190611b55565b9250611519565b60f8801b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff191610156114c5576004836114be9190611b55565b9250611518565b60fc60f81b817effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161015611507576005836115009190611b55565b9250611517565b6006836115149190611b55565b92505b5b5b5b5b50828061152790611ab7565b935050611394565b829350505050919050565b6040518060200160405280600190602082028036833780820191505090505090565b604051806106000160405280603090602082028036833780820191505090505090565b6000604051905090565b600080fd5b600080fd5b6000819050919050565b6115a681611593565b81146115b157600080fd5b50565b6000813590506115c38161159d565b92915050565b600080600080608085870312156115e3576115e2611589565b5b60006115f1878288016115b4565b9450506020611602878288016115b4565b9350506040611613878288016115b4565b9250506060611624878288016115b4565b91505092959194509250565b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b61167e82611635565b810181811067ffffffffffffffff8211171561169d5761169c611646565b5b80604052505050565b60006116b061157f565b90506116bc8282611675565b919050565b600067ffffffffffffffff8211156116dc576116db611646565b5b602082029050602081019050919050565b600080fd5b6000611705611700846116c1565b6116a6565b90508083825260208201905060208402830185811115611728576117276116ed565b5b835b81811015611751578061173d88826115b4565b84526020840193505060208101905061172a565b5050509392505050565b600082601f8301126117705761176f611630565b5b81356117808482602086016116f2565b91505092915050565b600080600080608085870312156117a3576117a2611589565b5b600085013567ffffffffffffffff8111156117c1576117c061158e565b5b6117cd8782880161175b565b94505060206117de878288016115b4565b93505060406117ef878288016115b4565b9250506060611800878288016115b4565b91505092959194509250565b61181581611593565b82525050565b6000602082019050611830600083018461180c565b92915050565b600080fd5b600067ffffffffffffffff82111561185657611855611646565b5b61185f82611635565b9050602081019050919050565b82818337600083830152505050565b600061188e6118898461183b565b6116a6565b9050828152602081018484840111156118aa576118a9611836565b5b6118b584828561186c565b509392505050565b600082601f8301126118d2576118d1611630565b5b81356118e284826020860161187b565b91505092915050565b60008060006060848603121561190457611903611589565b5b6000611912868287016115b4565b9350506020611923868287016115b4565b925050604084013567ffffffffffffffff8111156119445761194361158e565b5b611950868287016118bd565b9150509250925092565b6000602082840312156119705761196f611589565b5b600082013567ffffffffffffffff81111561198e5761198d61158e565b5b61199a8482850161175b565b91505092915050565b6000819050919050565b6000819050919050565b60006119d26119cd6119c8846119a3565b6119ad565b611593565b9050919050565b6119e2816119b7565b82525050565b60006020820190506119fd60008301846119d9565b92915050565b6000819050919050565b6000611a28611a23611a1e84611a03565b6119ad565b611593565b9050919050565b611a3881611a0d565b82525050565b6000602082019050611a536000830184611a2f565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000611ac282611593565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203611af457611af3611a88565b5b600182019050919050565b6000819050919050565b6000611b24611b1f611b1a84611aff565b6119ad565b611593565b9050919050565b611b3481611b09565b82525050565b6000602082019050611b4f6000830184611b2b565b92915050565b6000611b6082611593565b9150611b6b83611593565b9250828201905080821115611b8357611b82611a88565b5b92915050565b6000611b9482611593565b9150611b9f83611593565b9250828203905081811115611bb757611bb6611a88565b5b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b6000611bf782611593565b9150611c0283611593565b9250828202611c1081611593565b91508282048414831517611c2757611c26611a88565b5b5092915050565b6000611c3982611593565b9150611c4483611593565b925082611c5457611c53611bbd565b5b828206905092915050565b6000611c6a82611593565b915060008203611c7d57611c7c611a88565b5b600182039050919050565b600081519050919050565b600081905092915050565b60005b83811015611cbc578082015181840152602081019050611ca1565b60008484015250505050565b6000611cd382611c88565b611cdd8185611c93565b9350611ced818560208601611c9e565b80840191505092915050565b600060ff82169050919050565b60008160f81b9050919050565b6000611d1e82611d06565b9050919050565b611d36611d3182611cf9565b611d13565b82525050565b6000611d488285611cc8565b9150611d548284611d25565b6001820191508190509392505050565b6000819050919050565b611d7f611d7a82611593565b611d64565b82525050565b600081519050919050565b600081905092915050565b6000611da682611d85565b611db08185611d90565b9350611dc0818560208601611c9e565b80840191505092915050565b6000611dd8828b611cc8565b9150611de4828a611d6e565b602082019150611df48289611d6e565b602082019150611e048288611d25565b600182019150611e148287611d25565b600182019150611e248286611d25565b600182019150611e348285611d9b565b9150611e408284611d25565b6001820191508190509998505050505050505050565b6000611e628284611cc8565b915081905092915050565b6000819050919050565b611e8081611e6d565b8114611e8b57600080fd5b50565b600081519050611e9d81611e77565b92915050565b600060208284031215611eb957611eb8611589565b5b6000611ec784828501611e8e565b91505092915050565b6000819050919050565b611eeb611ee682611e6d565b611ed0565b82525050565b6000611efd8287611eda565b602082019150611f0d8286611d25565b600182019150611f1d8285611d9b565b9150611f298284611d25565b60018201915081905095945050505050565b6000611f478284611d25565b60018201915081905092915050565b6000611f628287611cc8565b9150611f6e8286611d25565b600182019150611f7e8285611d9b565b9150611f8a8284611d25565b6001820191508190509594505050505056fea2646970667358221220e743b9974b9ac7bcb6254f45cbb01be441926ba037731318a1a44400bd53c26264736f6c63430008130033",
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

// TestBatchComputeLagrange is a paid mutator transaction binding the contract method 0x32bc469a.
//
// Solidity: function test_batch_compute_lagrange(uint256 k, uint256 z, uint256 w, uint256 n) returns()
func (_Contract *ContractTransactor) TestBatchComputeLagrange(opts *bind.TransactOpts, k *big.Int, z *big.Int, w *big.Int, n *big.Int) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "test_batch_compute_lagrange", k, z, w, n)
}

// TestBatchComputeLagrange is a paid mutator transaction binding the contract method 0x32bc469a.
//
// Solidity: function test_batch_compute_lagrange(uint256 k, uint256 z, uint256 w, uint256 n) returns()
func (_Contract *ContractSession) TestBatchComputeLagrange(k *big.Int, z *big.Int, w *big.Int, n *big.Int) (*types.Transaction, error) {
	return _Contract.Contract.TestBatchComputeLagrange(&_Contract.TransactOpts, k, z, w, n)
}

// TestBatchComputeLagrange is a paid mutator transaction binding the contract method 0x32bc469a.
//
// Solidity: function test_batch_compute_lagrange(uint256 k, uint256 z, uint256 w, uint256 n) returns()
func (_Contract *ContractTransactorSession) TestBatchComputeLagrange(k *big.Int, z *big.Int, w *big.Int, n *big.Int) (*types.Transaction, error) {
	return _Contract.Contract.TestBatchComputeLagrange(&_Contract.TransactOpts, k, z, w, n)
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
