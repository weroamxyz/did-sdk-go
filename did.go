package did

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/mr-tron/base58"
	"github.com/weroamxyz/did-sdk-go/v2/registry"
)

// ==================== Key/Signature Functions ====================

// CreateJWSSignature uses a private key and a message to create a JWS format signature
func CreateJWSSignature(privKey *ecdsa.PrivateKey, message []byte) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256K-R","b64":false,"crit":["b64"]}`))

	// Replace the Signature with the SECP256k1r signature
	sig, err := crypto.Sign(message[:], privKey)
	if err != nil {
		return "", err
	}

	// Manually calaulate the V byte by adding 27 to the recovery ID
	sig[64] += 27

	encodedSig := base64.RawURLEncoding.EncodeToString(sig)
	compactserialized := header + "." + "." + encodedSig

	return compactserialized, nil
}

// VerifyJWSSignature verifies a JWS format signature using the matching public key and the original message
func VerifyJWSSignature(signature string, expectedFullBlkID string, message []byte) (bool, error) {
	partedExpectedBlkID := strings.Split(expectedFullBlkID, ":")
	if (len(partedExpectedBlkID) != 3 && len(partedExpectedBlkID) != 2) || partedExpectedBlkID[0] != "eip155" {
		return false, ErrInvalidBlockID
	}
	expectedAddress := common.HexToAddress(partedExpectedBlkID[len(partedExpectedBlkID)-1])

	partedSig := strings.Split(signature, ".")
	if len(partedSig) != 3 {
		return false, ErrInValidSignature
	}

	sig, err := base64.RawURLEncoding.DecodeString(partedSig[2])
	if err != nil {
		return false, ErrInValidSignature
	}

	// Manually calaulate the Recovery ID by subtracting 27 from the V byte
	if len(sig) != 65 {
		return false, ErrInValidSignature
	}

	if sig[64] != 0x00 && sig[64] != 0x01 {
		sig[64] -= 27
	}

	recoveredPubKey, err := crypto.SigToPub(message[:], sig)
	if err != nil {
		return false, ErrInValidSignature
	}

	recoveredAddress := crypto.PubkeyToAddress(*recoveredPubKey)
	return recoveredAddress == expectedAddress, nil
}

// VerifyEIP712Signature verifies an Ethereum EIP-712 signature
func VerifyEIP712Signature(signature string, expectedFullBlkID string, message []byte) (bool, error) {

	partedExpectedBlkID := strings.Split(expectedFullBlkID, ":")
	if (len(partedExpectedBlkID) != 3 && len(partedExpectedBlkID) != 2) || partedExpectedBlkID[0] != "eip155" {
		return false, ErrInvalidBlockID
	}

	expectedAddress := common.HexToAddress(partedExpectedBlkID[len(partedExpectedBlkID)-1])

	// Parse the signature
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false, err
	}
	if len(sig) != 65 {
		return false, errors.New("invalid signature length")
	}

	// Recover the public key
	recoveredPubKey, err := crypto.SigToPub(message, sig)
	if err != nil {
		return false, err
	}

	// Compute the address
	recoveredAddress := crypto.PubkeyToAddress(*recoveredPubKey)

	// Compare the addresses
	return recoveredAddress == expectedAddress, nil
}

// CreateEIP712Signature creates an EIP712 signature
func CreateEIP712Signature(privKey *ecdsa.PrivateKey, typedDataHash common.Hash) (string, error) {

	signature, err := crypto.Sign(typedDataHash.Bytes(), privKey)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(signature), nil
}

// VerifyEd25519JWSSignature verifies an Ed25519 JWS signature
func VerifyEd25519JWSSignature(signature string, pubKey ed25519.PublicKey, message []byte) (bool, error) {

	partedSig := strings.Split(signature, ".")
	if len(partedSig) != 3 {
		return false, ErrInValidSignature
	}

	sig, err := base64.RawURLEncoding.DecodeString(partedSig[2])
	if err != nil {
		return false, ErrInValidSignature
	}

	return ed25519.Verify(pubKey, message, sig), nil
}

// CreateEd25519JWSSignature creates an Ed25519 JWS signature
func CreateEd25519JWSSignature(privKey *ed25519.PrivateKey, message []byte) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","b64":false,"crit":["b64"]}`))
	sig := ed25519.Sign(*privKey, message)

	encodedSig := base64.RawURLEncoding.EncodeToString(sig)
	compactserialized := header + "." + "." + encodedSig

	return compactserialized, nil
}

// CompareAddresses compares two Ethereum addresses by checking the identifiers and chainIDs
func CompareAddresses(address1 string, address2 string) bool {
	// Parse the addresses
	parsedAddress1 := strings.Split(address1, ":")
	parsedAddress2 := strings.Split(address2, ":")
	if len(parsedAddress1) == len(parsedAddress2) {
		return address1 == address2
	}

	// Check the identifiers
	if parsedAddress1[0] != parsedAddress2[0] {
		return false
	}

	// Check the chainIDs
	if parsedAddress1[1] != parsedAddress2[1] {
		return false
	}

	// Check the addresses
	if parsedAddress1[2] != parsedAddress2[2] {
		return false
	}

	return true
}

// ==================== DID Functions ====================

// prepareTransactor creates a transaction auth object with gas price and balance checks.
// Returns the transactor, DID identifier, and any error that occurred.
func prepareTransactor(did string, privKey *ecdsa.PrivateKey, bound *BoundedContract) (*bind.TransactOpts, string, error) {
	splitDID, valid := PrepareDID(did)
	if !valid {
		return nil, "", ErrInvalidDID
	}
	identifier := splitDID[len(splitDID)-1]

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, bound.ChainID)
	if err != nil {
		return nil, "", err
	}

	price, err := bound.Client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, "", err
	}

	auth.GasPrice = price
	auth.GasLimit = DefaultGasLimit

	balance, err := bound.Client.BalanceAt(context.Background(), auth.From, nil)
	if err != nil {
		return nil, "", err
	}

	requiredBalance := new(big.Int).Mul(price, new(big.Int).SetInt64(DefaultGasLimitInt64))
	if balance.Cmp(requiredBalance) < 0 {
		return nil, "", ErrInsufficientBalance
	}

	return auth, identifier, nil
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

// ValidateDID checks the format of a DID string and returns an error if invalid.
func ValidateDID(did []string) error {
	if len(did) != 3 && len(did) != 4 {
		return ErrDIDWrongSectionCount
	}

	if did[0] != "did" {
		return ErrDIDInvalidPrefix
	}

	if did[1] != "metablox" {
		return ErrDIDInvalidMethodName
	}

	var chainName, identifierSection string
	if len(did) == 3 {
		chainName = "ethereum"
		identifierSection = did[2]
	} else {
		chainName = did[2]
		identifierSection = did[3]
	}

	if len(identifierSection) == 0 {
		return ErrDIDEmptyIdentifier
	}

	if !common.IsHexAddress(identifierSection) && chainName != "solana" {
		return ErrDIDInvalidIdentifier
	}

	return nil
}

// SplitDIDString splits did string into sections.
func SplitDIDString(did string) []string {
	return strings.Split(did, ":")
}

// PrepareDID splits did and checks that it is formatted correctly.
func PrepareDID(did string) ([]string, bool) {
	splitString := SplitDIDString(did)
	return splitString, ValidateDID(splitString) == nil
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

func GetDocument(targetAddress string, bound *BoundedContract) (*DIDDocument, [32]byte, error) {
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
	if len(splitDID) == 3 {
		targetAddress = splitDID[2]
	} else {
		targetAddress = splitDID[3]
	}
	generatedDocument, _, err := GetDocument(targetAddress, bound)
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
	readOptions := &ResolutionOptions{}
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
	auth, identifier, err := prepareTransactor(did, privKey, bound)
	if err != nil {
		return "", err
	}

	tx, err := bound.Instance.ChangeController(auth, common.HexToAddress(identifier), newController)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func ChangeControllerPermit(did string, newController common.Address, privKey *ecdsa.PrivateKey, deadline big.Int, signature []byte, bound *BoundedContract) (string, error) {
	auth, identifier, err := prepareTransactor(did, privKey, bound)
	if err != nil {
		return "", err
	}

	tx, err := bound.Instance.ChangeControllerPermit(auth, common.HexToAddress(identifier), newController, &deadline, signature)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func AddDelegate(did string, delegate common.Address, delegateType [32]byte, validity big.Int, privKey *ecdsa.PrivateKey, bound *BoundedContract) (string, error) {
	auth, identifier, err := prepareTransactor(did, privKey, bound)
	if err != nil {
		return "", err
	}

	tx, err := bound.Instance.AddDelegate(auth, common.HexToAddress(identifier), delegateType, delegate, &validity)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func AddDelegatePermit(did string, delegate common.Address, delegateType [32]byte, validity big.Int, privKey *ecdsa.PrivateKey, deadline big.Int, signature []byte, bound *BoundedContract) (string, error) {
	auth, identifier, err := prepareTransactor(did, privKey, bound)
	if err != nil {
		return "", err
	}

	tx, err := bound.Instance.AddDelegatePermit(auth, common.HexToAddress(identifier), delegateType, delegate, &validity, &deadline, signature)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func RevokeDelegate(did string, delegate common.Address, delegateType [32]byte, privKey *ecdsa.PrivateKey, bound *BoundedContract) (string, error) {
	auth, identifier, err := prepareTransactor(did, privKey, bound)
	if err != nil {
		return "", err
	}

	tx, err := bound.Instance.RevokeDelegate(auth, common.HexToAddress(identifier), delegateType, delegate)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func RevokeDelegatePermit(did string, delegate common.Address, delegateType [32]byte, privKey *ecdsa.PrivateKey, deadline big.Int, signature []byte, bound *BoundedContract) (string, error) {
	auth, identifier, err := prepareTransactor(did, privKey, bound)
	if err != nil {
		return "", err
	}

	tx, err := bound.Instance.RevokeDelegatePermit(auth, common.HexToAddress(identifier), delegateType, delegate, &deadline, signature)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func ChangeAttribute(did string, attribute [32]byte, attributeValue []byte, validity big.Int, privKey *ecdsa.PrivateKey, bound *BoundedContract) (string, error) {
	auth, identifier, err := prepareTransactor(did, privKey, bound)
	if err != nil {
		return "", err
	}

	tx, err := bound.Instance.SetAttribute(auth, common.HexToAddress(identifier), attribute, attributeValue, &validity)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func ChangeAttributePermit(did string, attribute [32]byte, attributeValue []byte, validity big.Int, privKey *ecdsa.PrivateKey, deadline big.Int, signature []byte, bound *BoundedContract) (string, error) {
	auth, identifier, err := prepareTransactor(did, privKey, bound)
	if err != nil {
		return "", err
	}

	tx, err := bound.Instance.SetAttributePermit(auth, common.HexToAddress(identifier), attribute, attributeValue, &validity, &deadline, signature)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func RevokeAttribute(did string, attribute [32]byte, attributeValue []byte, privKey *ecdsa.PrivateKey, bound *BoundedContract) (string, error) {
	auth, identifier, err := prepareTransactor(did, privKey, bound)
	if err != nil {
		return "", err
	}

	tx, err := bound.Instance.RevokeAttribute(auth, common.HexToAddress(identifier), attribute, attributeValue)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

func RevokeAttributePermit(did string, attribute [32]byte, attributeValue []byte, privKey *ecdsa.PrivateKey, deadline big.Int, signature []byte, bound *BoundedContract) (string, error) {
	auth, identifier, err := prepareTransactor(did, privKey, bound)
	if err != nil {
		return "", err
	}

	tx, err := bound.Instance.RevokeAttributePermit(auth, common.HexToAddress(identifier), attribute, attributeValue, &deadline, signature)
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
