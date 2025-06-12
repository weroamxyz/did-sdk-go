package did

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mr-tron/base58"
	"github.com/weroamxyz/did-sdk-go/v2/registry"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

var boundedContracts map[string]*BoundedContract

func InitBoundedContracts(chainList []string) error {

	boundedContracts = make(map[string]*BoundedContract)
	for _, chainName := range chainList {
		_, ok := ChainName2IdMap[chainName]
		if !ok {
			return ErrUnknownChainName
		}

		contractConfig, ok := ChainName2ContractConfigMap[chainName]
		if !ok {
			return ErrUnknownChainName
		}

		boundedContract, err := GetRegistryInstance(contractConfig)
		if err != nil {
			return err
		}

		boundedContracts[chainName] = boundedContract
	}

	return nil
}

func GetBoundedContract(chainName string) (*BoundedContract, error) {

	boundedContract, ok := boundedContracts[chainName]
	if !ok {
		return nil, ErrUnknownChainName
	}

	return boundedContract, nil
}

func GetRegistryInstance(config ContractConfig) (bound *BoundedContract, err error) {

	bound = new(BoundedContract)

	if !common.IsHexAddress(config.ContractAddr) {
		return bound, ErrETHAddress
	}
	bound.Client, err = ethclient.Dial(config.RpcUrl)
	if err != nil {
		return bound, err
	}
	bound.ContractAddr = common.HexToAddress(config.ContractAddr)
	bound.Instance, err = registry.NewRegistry(bound.ContractAddr, bound.Client)
	if err != nil {
		return bound, err
	}
	bound.ChainID, err = bound.Client.ChainID(context.Background())
	if err != nil {
		return bound, err
	}
	bound.ChainName = config.ChainName

	return bound, nil
}

func GenerateDIDString(pubKey interface{}, network string) string {

	switch pubKey := pubKey.(type) {
	case *ecdsa.PublicKey:
		if network == "solana" {
			return ""
		}
		return generateEthDIDString(pubKey, network)
	case *ed25519.PublicKey:
		if network != "solana" {
			return ""
		}
		return generateSolDIDString(pubKey, network)
	default:
		return ""
	}

}

func generateEthDIDString(pubKey *ecdsa.PublicKey, network string) string {

	ethAddress := crypto.PubkeyToAddress(*pubKey)

	// No network/chainID provided, default on Ethereum Mainnet
	if network == "" {
		return "did:metablox:" + ethAddress.Hex()
	} else {
		return "did:metablox:" + network + ":" + ethAddress.Hex()
	}

}

func generateSolDIDString(pubKey *ed25519.PublicKey, network string) string {

	solAddress := base58.Encode(*pubKey)

	return "did:metablox:" + network + ":" + solAddress

}

// TODO: check that this function can be safely removed. The foundation service doesn't need to create new DID documents; however, some other system may want to import this function
func CreateDID(publicKey interface{}, bound BoundedContract) *DIDDocument {

	document := new(DIDDocument)
	loc, _ := time.LoadLocation("UTC")

	document.ID = GenerateDIDString(publicKey, bound.ChainName)
	document.Context = make([]string, 0)
	document.Context = append(document.Context, ContextSecp256k1)
	document.Context = append(document.Context, ContextDID)
	document.Created = time.Now().In(loc).Format(time.RFC3339)
	document.Updated = document.Created
	document.Version = 1

	VM := VerificationMethod{}
	address := ""
	if bound.ChainName == "solana" {
		edPubkey := publicKey.(*ed25519.PublicKey)
		address = base58.Encode(*edPubkey)
		VM.BlockchainAccountId = "solana" + ":" + address
	} else {
		ecPubkey := publicKey.(*ecdsa.PublicKey)
		address = crypto.PubkeyToAddress(*ecPubkey).Hex()
		VM.BlockchainAccountId = "eip155:" + bound.ChainID.String() + ":" + address
	}

	VM.ID = document.ID + "#controller"
	VM.Controller = document.ID
	VM.MethodType = Secp256k1Key

	document.VerificationMethod = append(document.VerificationMethod, VM)
	document.Authentication = VM.ID
	document.AssertionMethod = VM.ID

	return document
}

// TODO: check that this function can be safely removed
func DocumentToJson(document *DIDDocument) ([]byte, error) {
	jsonDoc, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	return jsonDoc, nil
}

// TODO: check that this function can be safely removed
func JsonToDocument(jsonDoc []byte) (*DIDDocument, error) {
	document := CreateDIDDocument()
	err := json.Unmarshal(jsonDoc, document)
	if err != nil {
		return nil, err
	}
	return document, nil
}

// check format of DID string
func IsDIDValid(did []string) bool {
	if len(did) != 3 && len(did) != 4 {
		fmt.Println("Not exactly 3 or 4 sections in DID")
		return false
	}
	prefix := did[0]
	if prefix != "did" {
		fmt.Println("First section of DID was '" + prefix + "' instead of 'did'")
		return false
	}

	methodName := did[1]
	if methodName != "metablox" {
		fmt.Println("Second section of DID was '" + methodName + "'instead of 'metablox'")
		return false
	}

	chainName := ""
	identifierSection := ""
	if len(did) == 3 {
		chainName = "ethereum"
		identifierSection = did[2]
	} else {
		chainName = did[2]
		identifierSection = did[3]
	}
	if !common.IsHexAddress(identifierSection) && chainName != "solana" {
		fmt.Println("Identifier section is formatted incorrectly")
		return false
	}

	if len(identifierSection) == 0 {
		fmt.Println("Identifier is empty")
		return false
	}

	return true
}

// split did string into 3 sections. First two should be 'did' and 'metablox', last one wil be the identifier
func SplitDIDString(did string) []string {
	return strings.Split(did, ":")
}

// splits did and checks that it is formatted correctly
func PrepareDID(did string) ([]string, bool) {
	splitString := SplitDIDString(did)
	valid := IsDIDValid(splitString)
	return splitString, valid
}

func GetChainNameFromDID(did string) (string, error) {
	splitDID, valid := PrepareDID(did)
	if !valid {
		return "", ErrInvalidDID
	}
	if len(splitDID) == 3 {
		return "ethereum", nil
	}

	_, ok := ChainName2IdMap[splitDID[2]]
	if !ok {
		chainID, err := strconv.Atoi(splitDID[2])
		if err != nil {
			return "", ErrInvalidDID
		}
		chainName, ok := ChainId2NameMap[chainID]
		if !ok {
			return "", ErrUnknownChainName
		}
		return chainName, nil
	} else {
		return splitDID[2], nil

	}
}

func GetDocument(targetAddress string, chainName string) (*DIDDocument, [32]byte, error) {

	bound, err := GetBoundedContract(chainName)
	if err != nil {
		return nil, [32]byte{0}, err
	}

	//txBlk, err := bound.Instance.Changed(nil, common.HexToAddress(targetAddress))
	//if err != nil {
	//	return nil, [32]byte{0}, err
	//}

	document := new(DIDDocument)
	loc, _ := time.LoadLocation("UTC")

	//document.ID = "did:metablox:" + "0x" + bound.ChainID.Text(16) + ":" + targetAddress
	document.ID = "did:metablox:" + bound.ChainName + ":" + targetAddress
	document.Context = make([]string, 0)
	document.Context = append(document.Context, ContextSecp256k1)
	document.Context = append(document.Context, ContextDID)
	document.Created = time.Now().In(loc).Format(time.RFC3339) //todo: need to get this from contract
	document.Updated = document.Created                        //todo: need to get this from contract
	document.Version = 1                                       //todo: need to get this from contract

	VM := VerificationMethod{}
	VM.ID = document.ID + "#controller"
	if bound.ChainName == "solana" {
		VM.BlockchainAccountId = "solana" + ":" + targetAddress
		VM.MethodType = Ed25519Key
	} else {
		VM.BlockchainAccountId = "eip155:" + bound.ChainID.String() + ":" + targetAddress
		VM.MethodType = Secp256k1Key
	}
	VM.Controller = document.ID
	document.VerificationMethod = append(document.VerificationMethod, VM)
	document.Authentication = VM.ID
	document.AssertionMethod = VM.ID

	/*
		contractAbi, err := abi.JSON(strings.NewReader(string(registry.RegistryABI)))
		if err != nil {
			return nil, [32]byte{0}, err
		}
	*/

	//if txBlk.Int64() != big.NewInt(0).Int64() {
	//	// We should check on the Event to rebuild the Doc here
	//}
	placeholderHash := [32]byte{94, 241, 27, 134, 190, 223, 112, 91, 189, 49, 221, 31, 228, 35, 189, 213, 251, 60, 60, 210, 162, 45, 151, 3, 31, 78, 41, 239, 41, 75, 198, 139}
	return document, placeholderHash, nil
}

// generate the did document that matches the provided did string. Any errors are returned in the ResolutionMetadata.
// Note that options currently does nothing; including it is a requirement according to W3C specifications, but we don't do anything with it right now
func Resolve(did string, options *ResolutionOptions, bound *BoundedContract) (*ResolutionMetadata, *DIDDocument, *DocumentMetadata) {
	splitDID, valid := PrepareDID(did)
	if !valid {
		return &ResolutionMetadata{Error: "invalid Did"}, nil, &DocumentMetadata{}
	}

	targetAddress := ""
	chainName := ""
	if len(splitDID) == 3 {
		targetAddress = splitDID[2]
		chainName = "ethereum"
	} else {
		targetAddress = splitDID[3]
		chainName = splitDID[2]
	}
	generatedDocument, _, err := GetDocument(targetAddress, chainName)
	if err != nil {
		return &ResolutionMetadata{Error: err.Error()}, nil, nil
	}

	docID, success := PrepareDID(generatedDocument.ID)
	if !success {
		return &ResolutionMetadata{Error: "document DID is invalid"}, nil, nil
	}

	if docID[3] != targetAddress { //identifier of the document should match provided did
		return &ResolutionMetadata{Error: "generated document DID does not match provided DID"}, nil, nil
	}

	//compare document hash to the hash value given by contract.GetDocument() to ensure data integrity

	/*comparisonHash := sha256.Sum256(ConvertDocToBytes(*generatedDocument))	//disabling this at the moment to avoid needing to update placeholderHash while we're still modfiying document layout
	if comparisonHash != generatedHash {
		return &ResolutionMetadata{Error: "document failed hash check"}, nil, nil
	}*/
	return &ResolutionMetadata{}, generatedDocument, nil
}

// generate a did document and return it in a specific data format (currently just JSON)
func ResolveRepresentation(did string, options *RepresentationResolutionOptions, bound *BoundedContract) (*RepresentationResolutionMetadata, []byte, *DocumentMetadata) {
	//Should be similar to Resolve, but returns the document in a specific representation format.
	//Representation type is included in options and returned in resolution metadata
	readOptions := CreateResolutionOptions()
	readResolutionMeta, document, readDocumentMeta := Resolve(did, readOptions, bound)
	if readResolutionMeta.Error != "" {
		return &RepresentationResolutionMetadata{Error: readResolutionMeta.Error}, nil, nil
	}

	switch options.Accept {
	case "application/did+json":
		fallthrough
	default: //default to JSON format if options.Accept is empty/invalid
		byteStream, err := json.Marshal(document)
		if err != nil {
			return &RepresentationResolutionMetadata{Error: "failed to convert document into JSON"}, nil, nil
		}
		return &RepresentationResolutionMetadata{ContentType: "application/did+json"}, byteStream, readDocumentMeta
	}
}

func ChangeController(did string, newController common.Address, privKey *ecdsa.PrivateKey, bound *BoundedContract) (string, error) {

	splitDID, valid := PrepareDID(did)
	if !valid {
		return "", ErrInvalidDID
	}
	identifiers := splitDID[len(splitDID)-1]

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, bound.ChainID)
	if err != nil {
		return "", err
	}

	price, err := bound.Client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", err
	}

	auth.GasPrice = price
	auth.GasLimit = uint64(300000)

	balance, err := bound.Client.BalanceAt(context.Background(), auth.From, nil)
	if err != nil {
		return "", err
	}

	if balance.Cmp(new(big.Int).Mul(price, new(big.Int).SetInt64(300000))) < 0 {
		return "", errors.New("insufficient balance")
	}

	tx, err := bound.Instance.ChangeController(auth, common.HexToAddress(identifiers), newController)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func ChangeControllerPermit(did string, newController common.Address, privKey *ecdsa.PrivateKey, deadlinne big.Int, signature []byte, bound *BoundedContract) (string, error) {
	splitDID, valid := PrepareDID(did)
	if !valid {
		return "", ErrInvalidDID
	}
	identifiers := splitDID[len(splitDID)-1]

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, bound.ChainID)
	if err != nil {
		return "", err
	}

	price, err := bound.Client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", err
	}

	auth.GasPrice = price
	auth.GasLimit = uint64(300000)

	balance, err := bound.Client.BalanceAt(context.Background(), auth.From, nil)
	if err != nil {
		return "", err
	}

	if balance.Cmp(new(big.Int).Mul(price, new(big.Int).SetInt64(300000))) < 0 {
		return "", errors.New("insufficient balance")
	}

	tx, err := bound.Instance.ChangeControllerPermit(auth, common.HexToAddress(identifiers), newController, &deadlinne, signature)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func AddDelegate(did string, delegate common.Address, delegateType [32]byte, validity big.Int, privKey *ecdsa.PrivateKey, bound *BoundedContract) (string, error) {

	splitDID, valid := PrepareDID(did)
	if !valid {
		return "", ErrInvalidDID
	}
	identifiers := splitDID[len(splitDID)-1]

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, bound.ChainID)
	if err != nil {
		return "", err
	}

	price, err := bound.Client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", err
	}

	auth.GasPrice = price
	auth.GasLimit = uint64(300000)

	balance, err := bound.Client.BalanceAt(context.Background(), auth.From, nil)
	if err != nil {
		return "", err
	}

	if balance.Cmp(new(big.Int).Mul(price, new(big.Int).SetInt64(300000))) < 0 {
		return "", errors.New("insufficient balance")
	}

	tx, err := bound.Instance.AddDelegate(auth, common.HexToAddress(identifiers), delegateType, delegate, &validity)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func AddDelegatePermit(did string, delegate common.Address, delegateType [32]byte, validity big.Int, privKey *ecdsa.PrivateKey, deadline big.Int, signature []byte, bound *BoundedContract) (string, error) {
	splitDID, valid := PrepareDID(did)
	if !valid {
		return "", ErrInvalidDID
	}
	identifiers := splitDID[len(splitDID)-1]

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, bound.ChainID)
	if err != nil {
		return "", err
	}

	price, err := bound.Client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", err
	}

	auth.GasPrice = price
	auth.GasLimit = uint64(300000)

	balance, err := bound.Client.BalanceAt(context.Background(), auth.From, nil)
	if err != nil {
		return "", err
	}

	if balance.Cmp(new(big.Int).Mul(price, new(big.Int).SetInt64(300000))) < 0 {
		return "", errors.New("insufficient balance")
	}

	tx, err := bound.Instance.AddDelegatePermit(auth, common.HexToAddress(identifiers), delegateType, delegate, &validity, &deadline, signature)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func RevokeDelegate(did string, delegate common.Address, delegateType [32]byte, privKey *ecdsa.PrivateKey, bound *BoundedContract) (string, error) {

	splitDID, valid := PrepareDID(did)
	if !valid {
		return "", ErrInvalidDID
	}
	identifiers := splitDID[len(splitDID)-1]

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, bound.ChainID)
	if err != nil {
		return "", err
	}

	price, err := bound.Client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", err
	}

	auth.GasPrice = price
	auth.GasLimit = uint64(300000)

	balance, err := bound.Client.BalanceAt(context.Background(), auth.From, nil)
	if err != nil {
		return "", err
	}

	if balance.Cmp(new(big.Int).Mul(price, new(big.Int).SetInt64(300000))) < 0 {
		return "", errors.New("insufficient balance")
	}

	tx, err := bound.Instance.RevokeDelegate(auth, common.HexToAddress(identifiers), delegateType, delegate)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func RevokeDelegatePermit(did string, delegate common.Address, delegateType [32]byte, privKey *ecdsa.PrivateKey, deadline big.Int, signature []byte, bound *BoundedContract) (string, error) {
	splitDID, valid := PrepareDID(did)
	if !valid {
		return "", ErrInvalidDID
	}
	identifiers := splitDID[len(splitDID)-1]

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, bound.ChainID)
	if err != nil {
		return "", err
	}

	price, err := bound.Client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", err
	}

	auth.GasPrice = price
	auth.GasLimit = uint64(300000)

	balance, err := bound.Client.BalanceAt(context.Background(), auth.From, nil)
	if err != nil {
		return "", err
	}

	if balance.Cmp(new(big.Int).Mul(price, new(big.Int).SetInt64(300000))) < 0 {
		return "", errors.New("insufficient balance")
	}

	tx, err := bound.Instance.RevokeDelegatePermit(auth, common.HexToAddress(identifiers), delegateType, delegate, &deadline, signature)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func ChangeAttribute(did string, attribute [32]byte, attributeValue []byte, validity big.Int, privKey *ecdsa.PrivateKey, bound *BoundedContract) (string, error) {

	splitDID, valid := PrepareDID(did)
	if !valid {
		return "", ErrInvalidDID
	}
	identifiers := splitDID[len(splitDID)-1]

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, bound.ChainID)
	if err != nil {
		return "", err
	}

	price, err := bound.Client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", err
	}

	auth.GasPrice = price
	auth.GasLimit = uint64(300000)

	balance, err := bound.Client.BalanceAt(context.Background(), auth.From, nil)
	if err != nil {
		return "", err
	}

	if balance.Cmp(new(big.Int).Mul(price, new(big.Int).SetInt64(300000))) < 0 {
		return "", errors.New("insufficient balance")
	}

	tx, err := bound.Instance.SetAttribute(auth, common.HexToAddress(identifiers), attribute, attributeValue, &validity)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func ChangeAttributePermit(did string, attribute [32]byte, attributeValue []byte, validity big.Int, privKey *ecdsa.PrivateKey, deadline big.Int, signature []byte, bound *BoundedContract) (string, error) {
	splitDID, valid := PrepareDID(did)
	if !valid {
		return "", ErrInvalidDID
	}
	identifiers := splitDID[len(splitDID)-1]

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, bound.ChainID)
	if err != nil {
		return "", err
	}

	price, err := bound.Client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", err
	}

	auth.GasPrice = price
	auth.GasLimit = uint64(300000)

	balance, err := bound.Client.BalanceAt(context.Background(), auth.From, nil)
	if err != nil {
		return "", err
	}

	if balance.Cmp(new(big.Int).Mul(price, new(big.Int).SetInt64(300000))) < 0 {
		return "", errors.New("insufficient balance")
	}

	tx, err := bound.Instance.SetAttributePermit(auth, common.HexToAddress(identifiers), attribute, attributeValue, &validity, &deadline, signature)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func RevokeAttribute(did string, attribute [32]byte, attributeValue []byte, privKey *ecdsa.PrivateKey, bound *BoundedContract) (string, error) {
	splitDID, valid := PrepareDID(did)
	if !valid {
		return "", ErrInvalidDID
	}
	identifiers := splitDID[len(splitDID)-1]

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, bound.ChainID)
	if err != nil {
		return "", err
	}

	price, err := bound.Client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", err
	}

	auth.GasPrice = price
	auth.GasLimit = uint64(300000)

	balance, err := bound.Client.BalanceAt(context.Background(), auth.From, nil)
	if err != nil {
		return "", err
	}

	if balance.Cmp(new(big.Int).Mul(price, new(big.Int).SetInt64(300000))) < 0 {
		return "", errors.New("insufficient balance")
	}

	tx, err := bound.Instance.RevokeAttribute(auth, common.HexToAddress(identifiers), attribute, attributeValue)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func RevokeAttributePermit(did string, attribute [32]byte, attributeValue []byte, privKey *ecdsa.PrivateKey, deadline big.Int, signature []byte, bound *BoundedContract) (string, error) {
	splitDID, valid := PrepareDID(did)
	if !valid {
		return "", ErrInvalidDID
	}
	identifiers := splitDID[len(splitDID)-1]

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, bound.ChainID)
	if err != nil {
		return "", err
	}

	price, err := bound.Client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", err
	}

	auth.GasPrice = price
	auth.GasLimit = uint64(300000)

	balance, err := bound.Client.BalanceAt(context.Background(), auth.From, nil)
	if err != nil {
		return "", err
	}

	if balance.Cmp(new(big.Int).Mul(price, new(big.Int).SetInt64(300000))) < 0 {
		return "", errors.New("insufficient balance")
	}

	tx, err := bound.Instance.RevokeAttributePermit(auth, common.HexToAddress(identifiers), attribute, attributeValue, &deadline, signature)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

// convert document into byte array so it can be hashed (appears to be unused currently)
func ConvertDocToBytes(doc DIDDocument) []byte {
	var convertedBytes []byte

	sort.SliceStable(doc.Context, func(i, j int) bool { //have to sort arrays alphabetically before iterating over them to ensure a consistent ordering
		return doc.Context[i] < doc.Context[j]
	})
	for _, item := range doc.Context {
		convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(item)}, []byte{})
	}

	convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(doc.ID), []byte(doc.Created), []byte(doc.Updated), []byte(strconv.Itoa(doc.Version))}, []byte{})

	sort.SliceStable(doc.VerificationMethod, func(i, j int) bool {
		return doc.VerificationMethod[i].ID < doc.VerificationMethod[j].ID
	})
	for _, item := range doc.VerificationMethod {
		convertedBytes = bytes.Join([][]byte{convertedBytes, ConvertVMToBytes(item)}, []byte{})
	}

	convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(doc.Authentication)}, []byte{})

	sort.SliceStable(doc.Service, func(i, j int) bool {
		return doc.Service[i].ID < doc.Service[j].ID
	})
	for _, item := range doc.Service {
		convertedBytes = bytes.Join([][]byte{convertedBytes, ConvertServiceToBytes(item)}, []byte{})
	}
	return convertedBytes
}

// convert VM to byte array. Used as part of converting document to bytes
func ConvertVMToBytes(vm VerificationMethod) []byte {
	var convertedBytes []byte

	convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(vm.ID), []byte(vm.MethodType), []byte(vm.Controller), []byte(vm.BlockchainAccountId)}, []byte{})
	return convertedBytes
}

// convert service to byte array. Used as part of converting document to bytes
func ConvertServiceToBytes(service Service) []byte {
	var convertedBytes []byte

	convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(service.ID), []byte(service.Type), []byte(service.ServiceEndpoint)}, []byte{})
	return convertedBytes
}
