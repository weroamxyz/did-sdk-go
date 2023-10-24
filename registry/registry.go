// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package registry

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

// RegistryMetaData contains all meta data concerning the Registry contract.
var RegistryMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"currentNonce\",\"type\":\"uint256\"}],\"name\":\"InvalidAccountNonce\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InvalidShortString\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"str\",\"type\":\"string\"}],\"name\":\"StringTooLong\",\"type\":\"error\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"did\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"name\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"value\",\"type\":\"bytes\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"validTo\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"previousChange\",\"type\":\"uint256\"}],\"name\":\"DIDAttributeChanged\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"oldController\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"newController\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"previousChange\",\"type\":\"uint256\"}],\"name\":\"DIDControllerChanged\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"did\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"delegateType\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"delegate\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"validTo\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"previousChange\",\"type\":\"uint256\"}],\"name\":\"DIDDelegateChanged\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[],\"name\":\"EIP712DomainChanged\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"DOMAIN_SEPARATOR\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"did\",\"type\":\"address\"},{\"internalType\":\"bytes32\",\"name\":\"delegateType\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"delegate\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"validity\",\"type\":\"uint256\"}],\"name\":\"addDelegate\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"did\",\"type\":\"address\"},{\"internalType\":\"bytes32\",\"name\":\"delegateType\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"delegate\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"validity\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"deadline\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"signature\",\"type\":\"bytes\"}],\"name\":\"addDelegatePermit\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"did\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"newController\",\"type\":\"address\"}],\"name\":\"changeController\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"did\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"newController\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"deadline\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"signature\",\"type\":\"bytes\"}],\"name\":\"changeControllerPermit\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"changed\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"},{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"delegates\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"eip712Domain\",\"outputs\":[{\"internalType\":\"bytes1\",\"name\":\"fields\",\"type\":\"bytes1\"},{\"internalType\":\"string\",\"name\":\"name\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"version\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"chainId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"verifyingContract\",\"type\":\"address\"},{\"internalType\":\"bytes32\",\"name\":\"salt\",\"type\":\"bytes32\"},{\"internalType\":\"uint256[]\",\"name\":\"extensions\",\"type\":\"uint256[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"did\",\"type\":\"address\"}],\"name\":\"getController\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"}],\"name\":\"nonces\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"did\",\"type\":\"address\"},{\"internalType\":\"bytes32\",\"name\":\"name\",\"type\":\"bytes32\"},{\"internalType\":\"bytes\",\"name\":\"value\",\"type\":\"bytes\"}],\"name\":\"revokeAttribute\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"did\",\"type\":\"address\"},{\"internalType\":\"bytes32\",\"name\":\"name\",\"type\":\"bytes32\"},{\"internalType\":\"bytes\",\"name\":\"value\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"deadline\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"signature\",\"type\":\"bytes\"}],\"name\":\"revokeAttributePermit\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"did\",\"type\":\"address\"},{\"internalType\":\"bytes32\",\"name\":\"delegateType\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"delegate\",\"type\":\"address\"}],\"name\":\"revokeDelegate\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"did\",\"type\":\"address\"},{\"internalType\":\"bytes32\",\"name\":\"delegateType\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"delegate\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"deadline\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"signature\",\"type\":\"bytes\"}],\"name\":\"revokeDelegatePermit\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"did\",\"type\":\"address\"},{\"internalType\":\"bytes32\",\"name\":\"name\",\"type\":\"bytes32\"},{\"internalType\":\"bytes\",\"name\":\"value\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"validity\",\"type\":\"uint256\"}],\"name\":\"setAttribute\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"did\",\"type\":\"address\"},{\"internalType\":\"bytes32\",\"name\":\"name\",\"type\":\"bytes32\"},{\"internalType\":\"bytes\",\"name\":\"value\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"validity\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"deadline\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"signature\",\"type\":\"bytes\"}],\"name\":\"setAttributePermit\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"did\",\"type\":\"address\"},{\"internalType\":\"bytes32\",\"name\":\"delegateType\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"delegate\",\"type\":\"address\"}],\"name\":\"validDelegate\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
}

// RegistryABI is the input ABI used to generate the binding from.
// Deprecated: Use RegistryMetaData.ABI instead.
var RegistryABI = RegistryMetaData.ABI

// Registry is an auto generated Go binding around an Ethereum contract.
type Registry struct {
	RegistryCaller     // Read-only binding to the contract
	RegistryTransactor // Write-only binding to the contract
	RegistryFilterer   // Log filterer for contract events
}

// RegistryCaller is an auto generated read-only Go binding around an Ethereum contract.
type RegistryCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegistryTransactor is an auto generated write-only Go binding around an Ethereum contract.
type RegistryTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegistryFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type RegistryFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RegistrySession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type RegistrySession struct {
	Contract     *Registry         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// RegistryCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type RegistryCallerSession struct {
	Contract *RegistryCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// RegistryTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type RegistryTransactorSession struct {
	Contract     *RegistryTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// RegistryRaw is an auto generated low-level Go binding around an Ethereum contract.
type RegistryRaw struct {
	Contract *Registry // Generic contract binding to access the raw methods on
}

// RegistryCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type RegistryCallerRaw struct {
	Contract *RegistryCaller // Generic read-only contract binding to access the raw methods on
}

// RegistryTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type RegistryTransactorRaw struct {
	Contract *RegistryTransactor // Generic write-only contract binding to access the raw methods on
}

// NewRegistry creates a new instance of Registry, bound to a specific deployed contract.
func NewRegistry(address common.Address, backend bind.ContractBackend) (*Registry, error) {
	contract, err := bindRegistry(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Registry{RegistryCaller: RegistryCaller{contract: contract}, RegistryTransactor: RegistryTransactor{contract: contract}, RegistryFilterer: RegistryFilterer{contract: contract}}, nil
}

// NewRegistryCaller creates a new read-only instance of Registry, bound to a specific deployed contract.
func NewRegistryCaller(address common.Address, caller bind.ContractCaller) (*RegistryCaller, error) {
	contract, err := bindRegistry(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &RegistryCaller{contract: contract}, nil
}

// NewRegistryTransactor creates a new write-only instance of Registry, bound to a specific deployed contract.
func NewRegistryTransactor(address common.Address, transactor bind.ContractTransactor) (*RegistryTransactor, error) {
	contract, err := bindRegistry(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &RegistryTransactor{contract: contract}, nil
}

// NewRegistryFilterer creates a new log filterer instance of Registry, bound to a specific deployed contract.
func NewRegistryFilterer(address common.Address, filterer bind.ContractFilterer) (*RegistryFilterer, error) {
	contract, err := bindRegistry(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &RegistryFilterer{contract: contract}, nil
}

// bindRegistry binds a generic wrapper to an already deployed contract.
func bindRegistry(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := RegistryMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Registry *RegistryRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Registry.Contract.RegistryCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Registry *RegistryRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Registry.Contract.RegistryTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Registry *RegistryRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Registry.Contract.RegistryTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Registry *RegistryCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Registry.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Registry *RegistryTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Registry.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Registry *RegistryTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Registry.Contract.contract.Transact(opts, method, params...)
}

// DOMAINSEPARATOR is a free data retrieval call binding the contract method 0x3644e515.
//
// Solidity: function DOMAIN_SEPARATOR() view returns(bytes32)
func (_Registry *RegistryCaller) DOMAINSEPARATOR(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _Registry.contract.Call(opts, &out, "DOMAIN_SEPARATOR")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// DOMAINSEPARATOR is a free data retrieval call binding the contract method 0x3644e515.
//
// Solidity: function DOMAIN_SEPARATOR() view returns(bytes32)
func (_Registry *RegistrySession) DOMAINSEPARATOR() ([32]byte, error) {
	return _Registry.Contract.DOMAINSEPARATOR(&_Registry.CallOpts)
}

// DOMAINSEPARATOR is a free data retrieval call binding the contract method 0x3644e515.
//
// Solidity: function DOMAIN_SEPARATOR() view returns(bytes32)
func (_Registry *RegistryCallerSession) DOMAINSEPARATOR() ([32]byte, error) {
	return _Registry.Contract.DOMAINSEPARATOR(&_Registry.CallOpts)
}

// Changed is a free data retrieval call binding the contract method 0xf96d0f9f.
//
// Solidity: function changed(address ) view returns(uint256)
func (_Registry *RegistryCaller) Changed(opts *bind.CallOpts, arg0 common.Address) (*big.Int, error) {
	var out []interface{}
	err := _Registry.contract.Call(opts, &out, "changed", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Changed is a free data retrieval call binding the contract method 0xf96d0f9f.
//
// Solidity: function changed(address ) view returns(uint256)
func (_Registry *RegistrySession) Changed(arg0 common.Address) (*big.Int, error) {
	return _Registry.Contract.Changed(&_Registry.CallOpts, arg0)
}

// Changed is a free data retrieval call binding the contract method 0xf96d0f9f.
//
// Solidity: function changed(address ) view returns(uint256)
func (_Registry *RegistryCallerSession) Changed(arg0 common.Address) (*big.Int, error) {
	return _Registry.Contract.Changed(&_Registry.CallOpts, arg0)
}

// Delegates is a free data retrieval call binding the contract method 0x0d44625b.
//
// Solidity: function delegates(address , bytes32 , address ) view returns(uint256)
func (_Registry *RegistryCaller) Delegates(opts *bind.CallOpts, arg0 common.Address, arg1 [32]byte, arg2 common.Address) (*big.Int, error) {
	var out []interface{}
	err := _Registry.contract.Call(opts, &out, "delegates", arg0, arg1, arg2)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Delegates is a free data retrieval call binding the contract method 0x0d44625b.
//
// Solidity: function delegates(address , bytes32 , address ) view returns(uint256)
func (_Registry *RegistrySession) Delegates(arg0 common.Address, arg1 [32]byte, arg2 common.Address) (*big.Int, error) {
	return _Registry.Contract.Delegates(&_Registry.CallOpts, arg0, arg1, arg2)
}

// Delegates is a free data retrieval call binding the contract method 0x0d44625b.
//
// Solidity: function delegates(address , bytes32 , address ) view returns(uint256)
func (_Registry *RegistryCallerSession) Delegates(arg0 common.Address, arg1 [32]byte, arg2 common.Address) (*big.Int, error) {
	return _Registry.Contract.Delegates(&_Registry.CallOpts, arg0, arg1, arg2)
}

// Eip712Domain is a free data retrieval call binding the contract method 0x84b0196e.
//
// Solidity: function eip712Domain() view returns(bytes1 fields, string name, string version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] extensions)
func (_Registry *RegistryCaller) Eip712Domain(opts *bind.CallOpts) (struct {
	Fields            [1]byte
	Name              string
	Version           string
	ChainId           *big.Int
	VerifyingContract common.Address
	Salt              [32]byte
	Extensions        []*big.Int
}, error) {
	var out []interface{}
	err := _Registry.contract.Call(opts, &out, "eip712Domain")

	outstruct := new(struct {
		Fields            [1]byte
		Name              string
		Version           string
		ChainId           *big.Int
		VerifyingContract common.Address
		Salt              [32]byte
		Extensions        []*big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Fields = *abi.ConvertType(out[0], new([1]byte)).(*[1]byte)
	outstruct.Name = *abi.ConvertType(out[1], new(string)).(*string)
	outstruct.Version = *abi.ConvertType(out[2], new(string)).(*string)
	outstruct.ChainId = *abi.ConvertType(out[3], new(*big.Int)).(**big.Int)
	outstruct.VerifyingContract = *abi.ConvertType(out[4], new(common.Address)).(*common.Address)
	outstruct.Salt = *abi.ConvertType(out[5], new([32]byte)).(*[32]byte)
	outstruct.Extensions = *abi.ConvertType(out[6], new([]*big.Int)).(*[]*big.Int)

	return *outstruct, err

}

// Eip712Domain is a free data retrieval call binding the contract method 0x84b0196e.
//
// Solidity: function eip712Domain() view returns(bytes1 fields, string name, string version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] extensions)
func (_Registry *RegistrySession) Eip712Domain() (struct {
	Fields            [1]byte
	Name              string
	Version           string
	ChainId           *big.Int
	VerifyingContract common.Address
	Salt              [32]byte
	Extensions        []*big.Int
}, error) {
	return _Registry.Contract.Eip712Domain(&_Registry.CallOpts)
}

// Eip712Domain is a free data retrieval call binding the contract method 0x84b0196e.
//
// Solidity: function eip712Domain() view returns(bytes1 fields, string name, string version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] extensions)
func (_Registry *RegistryCallerSession) Eip712Domain() (struct {
	Fields            [1]byte
	Name              string
	Version           string
	ChainId           *big.Int
	VerifyingContract common.Address
	Salt              [32]byte
	Extensions        []*big.Int
}, error) {
	return _Registry.Contract.Eip712Domain(&_Registry.CallOpts)
}

// GetController is a free data retrieval call binding the contract method 0x88c662aa.
//
// Solidity: function getController(address did) view returns(address)
func (_Registry *RegistryCaller) GetController(opts *bind.CallOpts, did common.Address) (common.Address, error) {
	var out []interface{}
	err := _Registry.contract.Call(opts, &out, "getController", did)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetController is a free data retrieval call binding the contract method 0x88c662aa.
//
// Solidity: function getController(address did) view returns(address)
func (_Registry *RegistrySession) GetController(did common.Address) (common.Address, error) {
	return _Registry.Contract.GetController(&_Registry.CallOpts, did)
}

// GetController is a free data retrieval call binding the contract method 0x88c662aa.
//
// Solidity: function getController(address did) view returns(address)
func (_Registry *RegistryCallerSession) GetController(did common.Address) (common.Address, error) {
	return _Registry.Contract.GetController(&_Registry.CallOpts, did)
}

// Nonces is a free data retrieval call binding the contract method 0x7ecebe00.
//
// Solidity: function nonces(address owner) view returns(uint256)
func (_Registry *RegistryCaller) Nonces(opts *bind.CallOpts, owner common.Address) (*big.Int, error) {
	var out []interface{}
	err := _Registry.contract.Call(opts, &out, "nonces", owner)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Nonces is a free data retrieval call binding the contract method 0x7ecebe00.
//
// Solidity: function nonces(address owner) view returns(uint256)
func (_Registry *RegistrySession) Nonces(owner common.Address) (*big.Int, error) {
	return _Registry.Contract.Nonces(&_Registry.CallOpts, owner)
}

// Nonces is a free data retrieval call binding the contract method 0x7ecebe00.
//
// Solidity: function nonces(address owner) view returns(uint256)
func (_Registry *RegistryCallerSession) Nonces(owner common.Address) (*big.Int, error) {
	return _Registry.Contract.Nonces(&_Registry.CallOpts, owner)
}

// ValidDelegate is a free data retrieval call binding the contract method 0x622b2a3c.
//
// Solidity: function validDelegate(address did, bytes32 delegateType, address delegate) view returns(bool)
func (_Registry *RegistryCaller) ValidDelegate(opts *bind.CallOpts, did common.Address, delegateType [32]byte, delegate common.Address) (bool, error) {
	var out []interface{}
	err := _Registry.contract.Call(opts, &out, "validDelegate", did, delegateType, delegate)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// ValidDelegate is a free data retrieval call binding the contract method 0x622b2a3c.
//
// Solidity: function validDelegate(address did, bytes32 delegateType, address delegate) view returns(bool)
func (_Registry *RegistrySession) ValidDelegate(did common.Address, delegateType [32]byte, delegate common.Address) (bool, error) {
	return _Registry.Contract.ValidDelegate(&_Registry.CallOpts, did, delegateType, delegate)
}

// ValidDelegate is a free data retrieval call binding the contract method 0x622b2a3c.
//
// Solidity: function validDelegate(address did, bytes32 delegateType, address delegate) view returns(bool)
func (_Registry *RegistryCallerSession) ValidDelegate(did common.Address, delegateType [32]byte, delegate common.Address) (bool, error) {
	return _Registry.Contract.ValidDelegate(&_Registry.CallOpts, did, delegateType, delegate)
}

// AddDelegate is a paid mutator transaction binding the contract method 0xa7068d66.
//
// Solidity: function addDelegate(address did, bytes32 delegateType, address delegate, uint256 validity) returns()
func (_Registry *RegistryTransactor) AddDelegate(opts *bind.TransactOpts, did common.Address, delegateType [32]byte, delegate common.Address, validity *big.Int) (*types.Transaction, error) {
	return _Registry.contract.Transact(opts, "addDelegate", did, delegateType, delegate, validity)
}

// AddDelegate is a paid mutator transaction binding the contract method 0xa7068d66.
//
// Solidity: function addDelegate(address did, bytes32 delegateType, address delegate, uint256 validity) returns()
func (_Registry *RegistrySession) AddDelegate(did common.Address, delegateType [32]byte, delegate common.Address, validity *big.Int) (*types.Transaction, error) {
	return _Registry.Contract.AddDelegate(&_Registry.TransactOpts, did, delegateType, delegate, validity)
}

// AddDelegate is a paid mutator transaction binding the contract method 0xa7068d66.
//
// Solidity: function addDelegate(address did, bytes32 delegateType, address delegate, uint256 validity) returns()
func (_Registry *RegistryTransactorSession) AddDelegate(did common.Address, delegateType [32]byte, delegate common.Address, validity *big.Int) (*types.Transaction, error) {
	return _Registry.Contract.AddDelegate(&_Registry.TransactOpts, did, delegateType, delegate, validity)
}

// AddDelegatePermit is a paid mutator transaction binding the contract method 0xfe2f0b11.
//
// Solidity: function addDelegatePermit(address did, bytes32 delegateType, address delegate, uint256 validity, uint256 deadline, bytes signature) returns()
func (_Registry *RegistryTransactor) AddDelegatePermit(opts *bind.TransactOpts, did common.Address, delegateType [32]byte, delegate common.Address, validity *big.Int, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.contract.Transact(opts, "addDelegatePermit", did, delegateType, delegate, validity, deadline, signature)
}

// AddDelegatePermit is a paid mutator transaction binding the contract method 0xfe2f0b11.
//
// Solidity: function addDelegatePermit(address did, bytes32 delegateType, address delegate, uint256 validity, uint256 deadline, bytes signature) returns()
func (_Registry *RegistrySession) AddDelegatePermit(did common.Address, delegateType [32]byte, delegate common.Address, validity *big.Int, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.Contract.AddDelegatePermit(&_Registry.TransactOpts, did, delegateType, delegate, validity, deadline, signature)
}

// AddDelegatePermit is a paid mutator transaction binding the contract method 0xfe2f0b11.
//
// Solidity: function addDelegatePermit(address did, bytes32 delegateType, address delegate, uint256 validity, uint256 deadline, bytes signature) returns()
func (_Registry *RegistryTransactorSession) AddDelegatePermit(did common.Address, delegateType [32]byte, delegate common.Address, validity *big.Int, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.Contract.AddDelegatePermit(&_Registry.TransactOpts, did, delegateType, delegate, validity, deadline, signature)
}

// ChangeController is a paid mutator transaction binding the contract method 0x3e11e378.
//
// Solidity: function changeController(address did, address newController) returns()
func (_Registry *RegistryTransactor) ChangeController(opts *bind.TransactOpts, did common.Address, newController common.Address) (*types.Transaction, error) {
	return _Registry.contract.Transact(opts, "changeController", did, newController)
}

// ChangeController is a paid mutator transaction binding the contract method 0x3e11e378.
//
// Solidity: function changeController(address did, address newController) returns()
func (_Registry *RegistrySession) ChangeController(did common.Address, newController common.Address) (*types.Transaction, error) {
	return _Registry.Contract.ChangeController(&_Registry.TransactOpts, did, newController)
}

// ChangeController is a paid mutator transaction binding the contract method 0x3e11e378.
//
// Solidity: function changeController(address did, address newController) returns()
func (_Registry *RegistryTransactorSession) ChangeController(did common.Address, newController common.Address) (*types.Transaction, error) {
	return _Registry.Contract.ChangeController(&_Registry.TransactOpts, did, newController)
}

// ChangeControllerPermit is a paid mutator transaction binding the contract method 0x67c02b0a.
//
// Solidity: function changeControllerPermit(address did, address newController, uint256 deadline, bytes signature) returns()
func (_Registry *RegistryTransactor) ChangeControllerPermit(opts *bind.TransactOpts, did common.Address, newController common.Address, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.contract.Transact(opts, "changeControllerPermit", did, newController, deadline, signature)
}

// ChangeControllerPermit is a paid mutator transaction binding the contract method 0x67c02b0a.
//
// Solidity: function changeControllerPermit(address did, address newController, uint256 deadline, bytes signature) returns()
func (_Registry *RegistrySession) ChangeControllerPermit(did common.Address, newController common.Address, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.Contract.ChangeControllerPermit(&_Registry.TransactOpts, did, newController, deadline, signature)
}

// ChangeControllerPermit is a paid mutator transaction binding the contract method 0x67c02b0a.
//
// Solidity: function changeControllerPermit(address did, address newController, uint256 deadline, bytes signature) returns()
func (_Registry *RegistryTransactorSession) ChangeControllerPermit(did common.Address, newController common.Address, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.Contract.ChangeControllerPermit(&_Registry.TransactOpts, did, newController, deadline, signature)
}

// RevokeAttribute is a paid mutator transaction binding the contract method 0x00c023da.
//
// Solidity: function revokeAttribute(address did, bytes32 name, bytes value) returns()
func (_Registry *RegistryTransactor) RevokeAttribute(opts *bind.TransactOpts, did common.Address, name [32]byte, value []byte) (*types.Transaction, error) {
	return _Registry.contract.Transact(opts, "revokeAttribute", did, name, value)
}

// RevokeAttribute is a paid mutator transaction binding the contract method 0x00c023da.
//
// Solidity: function revokeAttribute(address did, bytes32 name, bytes value) returns()
func (_Registry *RegistrySession) RevokeAttribute(did common.Address, name [32]byte, value []byte) (*types.Transaction, error) {
	return _Registry.Contract.RevokeAttribute(&_Registry.TransactOpts, did, name, value)
}

// RevokeAttribute is a paid mutator transaction binding the contract method 0x00c023da.
//
// Solidity: function revokeAttribute(address did, bytes32 name, bytes value) returns()
func (_Registry *RegistryTransactorSession) RevokeAttribute(did common.Address, name [32]byte, value []byte) (*types.Transaction, error) {
	return _Registry.Contract.RevokeAttribute(&_Registry.TransactOpts, did, name, value)
}

// RevokeAttributePermit is a paid mutator transaction binding the contract method 0x97880f96.
//
// Solidity: function revokeAttributePermit(address did, bytes32 name, bytes value, uint256 deadline, bytes signature) returns()
func (_Registry *RegistryTransactor) RevokeAttributePermit(opts *bind.TransactOpts, did common.Address, name [32]byte, value []byte, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.contract.Transact(opts, "revokeAttributePermit", did, name, value, deadline, signature)
}

// RevokeAttributePermit is a paid mutator transaction binding the contract method 0x97880f96.
//
// Solidity: function revokeAttributePermit(address did, bytes32 name, bytes value, uint256 deadline, bytes signature) returns()
func (_Registry *RegistrySession) RevokeAttributePermit(did common.Address, name [32]byte, value []byte, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.Contract.RevokeAttributePermit(&_Registry.TransactOpts, did, name, value, deadline, signature)
}

// RevokeAttributePermit is a paid mutator transaction binding the contract method 0x97880f96.
//
// Solidity: function revokeAttributePermit(address did, bytes32 name, bytes value, uint256 deadline, bytes signature) returns()
func (_Registry *RegistryTransactorSession) RevokeAttributePermit(did common.Address, name [32]byte, value []byte, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.Contract.RevokeAttributePermit(&_Registry.TransactOpts, did, name, value, deadline, signature)
}

// RevokeDelegate is a paid mutator transaction binding the contract method 0x80b29f7c.
//
// Solidity: function revokeDelegate(address did, bytes32 delegateType, address delegate) returns()
func (_Registry *RegistryTransactor) RevokeDelegate(opts *bind.TransactOpts, did common.Address, delegateType [32]byte, delegate common.Address) (*types.Transaction, error) {
	return _Registry.contract.Transact(opts, "revokeDelegate", did, delegateType, delegate)
}

// RevokeDelegate is a paid mutator transaction binding the contract method 0x80b29f7c.
//
// Solidity: function revokeDelegate(address did, bytes32 delegateType, address delegate) returns()
func (_Registry *RegistrySession) RevokeDelegate(did common.Address, delegateType [32]byte, delegate common.Address) (*types.Transaction, error) {
	return _Registry.Contract.RevokeDelegate(&_Registry.TransactOpts, did, delegateType, delegate)
}

// RevokeDelegate is a paid mutator transaction binding the contract method 0x80b29f7c.
//
// Solidity: function revokeDelegate(address did, bytes32 delegateType, address delegate) returns()
func (_Registry *RegistryTransactorSession) RevokeDelegate(did common.Address, delegateType [32]byte, delegate common.Address) (*types.Transaction, error) {
	return _Registry.Contract.RevokeDelegate(&_Registry.TransactOpts, did, delegateType, delegate)
}

// RevokeDelegatePermit is a paid mutator transaction binding the contract method 0xee75d2e8.
//
// Solidity: function revokeDelegatePermit(address did, bytes32 delegateType, address delegate, uint256 deadline, bytes signature) returns()
func (_Registry *RegistryTransactor) RevokeDelegatePermit(opts *bind.TransactOpts, did common.Address, delegateType [32]byte, delegate common.Address, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.contract.Transact(opts, "revokeDelegatePermit", did, delegateType, delegate, deadline, signature)
}

// RevokeDelegatePermit is a paid mutator transaction binding the contract method 0xee75d2e8.
//
// Solidity: function revokeDelegatePermit(address did, bytes32 delegateType, address delegate, uint256 deadline, bytes signature) returns()
func (_Registry *RegistrySession) RevokeDelegatePermit(did common.Address, delegateType [32]byte, delegate common.Address, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.Contract.RevokeDelegatePermit(&_Registry.TransactOpts, did, delegateType, delegate, deadline, signature)
}

// RevokeDelegatePermit is a paid mutator transaction binding the contract method 0xee75d2e8.
//
// Solidity: function revokeDelegatePermit(address did, bytes32 delegateType, address delegate, uint256 deadline, bytes signature) returns()
func (_Registry *RegistryTransactorSession) RevokeDelegatePermit(did common.Address, delegateType [32]byte, delegate common.Address, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.Contract.RevokeDelegatePermit(&_Registry.TransactOpts, did, delegateType, delegate, deadline, signature)
}

// SetAttribute is a paid mutator transaction binding the contract method 0x7ad4b0a4.
//
// Solidity: function setAttribute(address did, bytes32 name, bytes value, uint256 validity) returns()
func (_Registry *RegistryTransactor) SetAttribute(opts *bind.TransactOpts, did common.Address, name [32]byte, value []byte, validity *big.Int) (*types.Transaction, error) {
	return _Registry.contract.Transact(opts, "setAttribute", did, name, value, validity)
}

// SetAttribute is a paid mutator transaction binding the contract method 0x7ad4b0a4.
//
// Solidity: function setAttribute(address did, bytes32 name, bytes value, uint256 validity) returns()
func (_Registry *RegistrySession) SetAttribute(did common.Address, name [32]byte, value []byte, validity *big.Int) (*types.Transaction, error) {
	return _Registry.Contract.SetAttribute(&_Registry.TransactOpts, did, name, value, validity)
}

// SetAttribute is a paid mutator transaction binding the contract method 0x7ad4b0a4.
//
// Solidity: function setAttribute(address did, bytes32 name, bytes value, uint256 validity) returns()
func (_Registry *RegistryTransactorSession) SetAttribute(did common.Address, name [32]byte, value []byte, validity *big.Int) (*types.Transaction, error) {
	return _Registry.Contract.SetAttribute(&_Registry.TransactOpts, did, name, value, validity)
}

// SetAttributePermit is a paid mutator transaction binding the contract method 0x030b320d.
//
// Solidity: function setAttributePermit(address did, bytes32 name, bytes value, uint256 validity, uint256 deadline, bytes signature) returns()
func (_Registry *RegistryTransactor) SetAttributePermit(opts *bind.TransactOpts, did common.Address, name [32]byte, value []byte, validity *big.Int, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.contract.Transact(opts, "setAttributePermit", did, name, value, validity, deadline, signature)
}

// SetAttributePermit is a paid mutator transaction binding the contract method 0x030b320d.
//
// Solidity: function setAttributePermit(address did, bytes32 name, bytes value, uint256 validity, uint256 deadline, bytes signature) returns()
func (_Registry *RegistrySession) SetAttributePermit(did common.Address, name [32]byte, value []byte, validity *big.Int, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.Contract.SetAttributePermit(&_Registry.TransactOpts, did, name, value, validity, deadline, signature)
}

// SetAttributePermit is a paid mutator transaction binding the contract method 0x030b320d.
//
// Solidity: function setAttributePermit(address did, bytes32 name, bytes value, uint256 validity, uint256 deadline, bytes signature) returns()
func (_Registry *RegistryTransactorSession) SetAttributePermit(did common.Address, name [32]byte, value []byte, validity *big.Int, deadline *big.Int, signature []byte) (*types.Transaction, error) {
	return _Registry.Contract.SetAttributePermit(&_Registry.TransactOpts, did, name, value, validity, deadline, signature)
}

// RegistryDIDAttributeChangedIterator is returned from FilterDIDAttributeChanged and is used to iterate over the raw logs and unpacked data for DIDAttributeChanged events raised by the Registry contract.
type RegistryDIDAttributeChangedIterator struct {
	Event *RegistryDIDAttributeChanged // Event containing the contract specifics and raw log

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
func (it *RegistryDIDAttributeChangedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegistryDIDAttributeChanged)
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
		it.Event = new(RegistryDIDAttributeChanged)
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
func (it *RegistryDIDAttributeChangedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegistryDIDAttributeChangedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegistryDIDAttributeChanged represents a DIDAttributeChanged event raised by the Registry contract.
type RegistryDIDAttributeChanged struct {
	Did            common.Address
	Name           [32]byte
	Value          []byte
	ValidTo        *big.Int
	PreviousChange *big.Int
	Raw            types.Log // Blockchain specific contextual infos
}

// FilterDIDAttributeChanged is a free log retrieval operation binding the contract event 0x18ab6b2ae3d64306c00ce663125f2bd680e441a098de1635bd7ad8b0d44965e4.
//
// Solidity: event DIDAttributeChanged(address indexed did, bytes32 name, bytes value, uint256 validTo, uint256 previousChange)
func (_Registry *RegistryFilterer) FilterDIDAttributeChanged(opts *bind.FilterOpts, did []common.Address) (*RegistryDIDAttributeChangedIterator, error) {

	var didRule []interface{}
	for _, didItem := range did {
		didRule = append(didRule, didItem)
	}

	logs, sub, err := _Registry.contract.FilterLogs(opts, "DIDAttributeChanged", didRule)
	if err != nil {
		return nil, err
	}
	return &RegistryDIDAttributeChangedIterator{contract: _Registry.contract, event: "DIDAttributeChanged", logs: logs, sub: sub}, nil
}

// WatchDIDAttributeChanged is a free log subscription operation binding the contract event 0x18ab6b2ae3d64306c00ce663125f2bd680e441a098de1635bd7ad8b0d44965e4.
//
// Solidity: event DIDAttributeChanged(address indexed did, bytes32 name, bytes value, uint256 validTo, uint256 previousChange)
func (_Registry *RegistryFilterer) WatchDIDAttributeChanged(opts *bind.WatchOpts, sink chan<- *RegistryDIDAttributeChanged, did []common.Address) (event.Subscription, error) {

	var didRule []interface{}
	for _, didItem := range did {
		didRule = append(didRule, didItem)
	}

	logs, sub, err := _Registry.contract.WatchLogs(opts, "DIDAttributeChanged", didRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegistryDIDAttributeChanged)
				if err := _Registry.contract.UnpackLog(event, "DIDAttributeChanged", log); err != nil {
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

// ParseDIDAttributeChanged is a log parse operation binding the contract event 0x18ab6b2ae3d64306c00ce663125f2bd680e441a098de1635bd7ad8b0d44965e4.
//
// Solidity: event DIDAttributeChanged(address indexed did, bytes32 name, bytes value, uint256 validTo, uint256 previousChange)
func (_Registry *RegistryFilterer) ParseDIDAttributeChanged(log types.Log) (*RegistryDIDAttributeChanged, error) {
	event := new(RegistryDIDAttributeChanged)
	if err := _Registry.contract.UnpackLog(event, "DIDAttributeChanged", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegistryDIDControllerChangedIterator is returned from FilterDIDControllerChanged and is used to iterate over the raw logs and unpacked data for DIDControllerChanged events raised by the Registry contract.
type RegistryDIDControllerChangedIterator struct {
	Event *RegistryDIDControllerChanged // Event containing the contract specifics and raw log

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
func (it *RegistryDIDControllerChangedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegistryDIDControllerChanged)
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
		it.Event = new(RegistryDIDControllerChanged)
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
func (it *RegistryDIDControllerChangedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegistryDIDControllerChangedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegistryDIDControllerChanged represents a DIDControllerChanged event raised by the Registry contract.
type RegistryDIDControllerChanged struct {
	OldController  common.Address
	NewController  common.Address
	PreviousChange *big.Int
	Raw            types.Log // Blockchain specific contextual infos
}

// FilterDIDControllerChanged is a free log retrieval operation binding the contract event 0x2a7278c7e47d91c392e2d4f854ebe76d04458b3f431d27ef2e64707e68615e48.
//
// Solidity: event DIDControllerChanged(address indexed oldController, address newController, uint256 previousChange)
func (_Registry *RegistryFilterer) FilterDIDControllerChanged(opts *bind.FilterOpts, oldController []common.Address) (*RegistryDIDControllerChangedIterator, error) {

	var oldControllerRule []interface{}
	for _, oldControllerItem := range oldController {
		oldControllerRule = append(oldControllerRule, oldControllerItem)
	}

	logs, sub, err := _Registry.contract.FilterLogs(opts, "DIDControllerChanged", oldControllerRule)
	if err != nil {
		return nil, err
	}
	return &RegistryDIDControllerChangedIterator{contract: _Registry.contract, event: "DIDControllerChanged", logs: logs, sub: sub}, nil
}

// WatchDIDControllerChanged is a free log subscription operation binding the contract event 0x2a7278c7e47d91c392e2d4f854ebe76d04458b3f431d27ef2e64707e68615e48.
//
// Solidity: event DIDControllerChanged(address indexed oldController, address newController, uint256 previousChange)
func (_Registry *RegistryFilterer) WatchDIDControllerChanged(opts *bind.WatchOpts, sink chan<- *RegistryDIDControllerChanged, oldController []common.Address) (event.Subscription, error) {

	var oldControllerRule []interface{}
	for _, oldControllerItem := range oldController {
		oldControllerRule = append(oldControllerRule, oldControllerItem)
	}

	logs, sub, err := _Registry.contract.WatchLogs(opts, "DIDControllerChanged", oldControllerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegistryDIDControllerChanged)
				if err := _Registry.contract.UnpackLog(event, "DIDControllerChanged", log); err != nil {
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

// ParseDIDControllerChanged is a log parse operation binding the contract event 0x2a7278c7e47d91c392e2d4f854ebe76d04458b3f431d27ef2e64707e68615e48.
//
// Solidity: event DIDControllerChanged(address indexed oldController, address newController, uint256 previousChange)
func (_Registry *RegistryFilterer) ParseDIDControllerChanged(log types.Log) (*RegistryDIDControllerChanged, error) {
	event := new(RegistryDIDControllerChanged)
	if err := _Registry.contract.UnpackLog(event, "DIDControllerChanged", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegistryDIDDelegateChangedIterator is returned from FilterDIDDelegateChanged and is used to iterate over the raw logs and unpacked data for DIDDelegateChanged events raised by the Registry contract.
type RegistryDIDDelegateChangedIterator struct {
	Event *RegistryDIDDelegateChanged // Event containing the contract specifics and raw log

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
func (it *RegistryDIDDelegateChangedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegistryDIDDelegateChanged)
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
		it.Event = new(RegistryDIDDelegateChanged)
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
func (it *RegistryDIDDelegateChangedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegistryDIDDelegateChangedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegistryDIDDelegateChanged represents a DIDDelegateChanged event raised by the Registry contract.
type RegistryDIDDelegateChanged struct {
	Did            common.Address
	DelegateType   [32]byte
	Delegate       common.Address
	ValidTo        *big.Int
	PreviousChange *big.Int
	Raw            types.Log // Blockchain specific contextual infos
}

// FilterDIDDelegateChanged is a free log retrieval operation binding the contract event 0x5a5084339536bcab65f20799fcc58724588145ca054bd2be626174b27ba156f7.
//
// Solidity: event DIDDelegateChanged(address indexed did, bytes32 delegateType, address delegate, uint256 validTo, uint256 previousChange)
func (_Registry *RegistryFilterer) FilterDIDDelegateChanged(opts *bind.FilterOpts, did []common.Address) (*RegistryDIDDelegateChangedIterator, error) {

	var didRule []interface{}
	for _, didItem := range did {
		didRule = append(didRule, didItem)
	}

	logs, sub, err := _Registry.contract.FilterLogs(opts, "DIDDelegateChanged", didRule)
	if err != nil {
		return nil, err
	}
	return &RegistryDIDDelegateChangedIterator{contract: _Registry.contract, event: "DIDDelegateChanged", logs: logs, sub: sub}, nil
}

// WatchDIDDelegateChanged is a free log subscription operation binding the contract event 0x5a5084339536bcab65f20799fcc58724588145ca054bd2be626174b27ba156f7.
//
// Solidity: event DIDDelegateChanged(address indexed did, bytes32 delegateType, address delegate, uint256 validTo, uint256 previousChange)
func (_Registry *RegistryFilterer) WatchDIDDelegateChanged(opts *bind.WatchOpts, sink chan<- *RegistryDIDDelegateChanged, did []common.Address) (event.Subscription, error) {

	var didRule []interface{}
	for _, didItem := range did {
		didRule = append(didRule, didItem)
	}

	logs, sub, err := _Registry.contract.WatchLogs(opts, "DIDDelegateChanged", didRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegistryDIDDelegateChanged)
				if err := _Registry.contract.UnpackLog(event, "DIDDelegateChanged", log); err != nil {
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

// ParseDIDDelegateChanged is a log parse operation binding the contract event 0x5a5084339536bcab65f20799fcc58724588145ca054bd2be626174b27ba156f7.
//
// Solidity: event DIDDelegateChanged(address indexed did, bytes32 delegateType, address delegate, uint256 validTo, uint256 previousChange)
func (_Registry *RegistryFilterer) ParseDIDDelegateChanged(log types.Log) (*RegistryDIDDelegateChanged, error) {
	event := new(RegistryDIDDelegateChanged)
	if err := _Registry.contract.UnpackLog(event, "DIDDelegateChanged", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RegistryEIP712DomainChangedIterator is returned from FilterEIP712DomainChanged and is used to iterate over the raw logs and unpacked data for EIP712DomainChanged events raised by the Registry contract.
type RegistryEIP712DomainChangedIterator struct {
	Event *RegistryEIP712DomainChanged // Event containing the contract specifics and raw log

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
func (it *RegistryEIP712DomainChangedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RegistryEIP712DomainChanged)
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
		it.Event = new(RegistryEIP712DomainChanged)
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
func (it *RegistryEIP712DomainChangedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RegistryEIP712DomainChangedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RegistryEIP712DomainChanged represents a EIP712DomainChanged event raised by the Registry contract.
type RegistryEIP712DomainChanged struct {
	Raw types.Log // Blockchain specific contextual infos
}

// FilterEIP712DomainChanged is a free log retrieval operation binding the contract event 0x0a6387c9ea3628b88a633bb4f3b151770f70085117a15f9bf3787cda53f13d31.
//
// Solidity: event EIP712DomainChanged()
func (_Registry *RegistryFilterer) FilterEIP712DomainChanged(opts *bind.FilterOpts) (*RegistryEIP712DomainChangedIterator, error) {

	logs, sub, err := _Registry.contract.FilterLogs(opts, "EIP712DomainChanged")
	if err != nil {
		return nil, err
	}
	return &RegistryEIP712DomainChangedIterator{contract: _Registry.contract, event: "EIP712DomainChanged", logs: logs, sub: sub}, nil
}

// WatchEIP712DomainChanged is a free log subscription operation binding the contract event 0x0a6387c9ea3628b88a633bb4f3b151770f70085117a15f9bf3787cda53f13d31.
//
// Solidity: event EIP712DomainChanged()
func (_Registry *RegistryFilterer) WatchEIP712DomainChanged(opts *bind.WatchOpts, sink chan<- *RegistryEIP712DomainChanged) (event.Subscription, error) {

	logs, sub, err := _Registry.contract.WatchLogs(opts, "EIP712DomainChanged")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RegistryEIP712DomainChanged)
				if err := _Registry.contract.UnpackLog(event, "EIP712DomainChanged", log); err != nil {
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

// ParseEIP712DomainChanged is a log parse operation binding the contract event 0x0a6387c9ea3628b88a633bb4f3b151770f70085117a15f9bf3787cda53f13d31.
//
// Solidity: event EIP712DomainChanged()
func (_Registry *RegistryFilterer) ParseEIP712DomainChanged(log types.Log) (*RegistryEIP712DomainChanged, error) {
	event := new(RegistryEIP712DomainChanged)
	if err := _Registry.contract.UnpackLog(event, "EIP712DomainChanged", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
