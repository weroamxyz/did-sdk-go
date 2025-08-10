package did

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"crypto/ed25519"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/gibson042/canonicaljson-go"
	"github.com/mitchellh/mapstructure"
	"github.com/multiformats/go-multibase"
)

var issuerDIDs []string
var issuerECPrivateKey *ecdsa.PrivateKey
var issuerEDPrivateKey *ed25519.PrivateKey
var issuerChainId *big.Int

func GetIssuerDids() []string {
	return issuerDIDs
}
func GetIssuerDidFromChainName(targetChainName string) (string, error) {
	issuerDIDs := GetIssuerDids()
	for _, did := range issuerDIDs {
		didChainName, err := GetChainNameFromDID(did)
		if err != nil {
			continue
		}
		if didChainName == targetChainName {
			return did, nil
		}
	}

	return "", ErrUnknownChainName
}
func GetIssuerDidFromChainID(targetChainID int) (string, error) {
	issuerDIDs := GetIssuerDids()
	targetChainName, ok := ChainId2NameMap[targetChainID]
	if !ok {
		return "", ErrUnknownChainID
	}
	for _, did := range issuerDIDs {
		didChainName, err := GetChainNameFromDID(did)
		if err != nil {
			continue
		}
		if didChainName == targetChainName {
			return did, nil
		}
	}

	return "", ErrUnknownChainID
}
func GetIssuerECPrivateKey() *ecdsa.PrivateKey {
	return issuerECPrivateKey
}
func GetIssuerEDPrivateKey() *ed25519.PrivateKey {
	return issuerEDPrivateKey
}
func GetIssuerChainId() *big.Int {
	return issuerChainId
}
func SetIssuerECPrivateKey(privateKey *ecdsa.PrivateKey) {
	issuerECPrivateKey = privateKey
}
func SetIssuerEDPrivateKey(privateKey *ed25519.PrivateKey) {
	issuerEDPrivateKey = privateKey
}

// All credential ids use a format of this value plus a number. ex. 'http://metablox.com/credentials/5'
// Only the number is stored in the db as the ID; the full string is only used in formal credentials
const BaseIDString = "https://metablox.io/credentials/"

type Config struct {
	Passphrase string `json:"passphrase"`
	Keystore   string `json:"keystore"`
	//ChainId    *big.Int `json:"chainId"`
	//ChainName  string   `json:"chainName"`
	ChainList []string `json:"chainList"`
}

func Init(cfg *Config) error {
	var err error
	issuerECPrivateKey, err = keystoreToPrivateKey(cfg.Keystore, cfg.Passphrase)
	if err != nil {
		return err
	}
	//issuerECPrivateKeyHex := common.Bytes2Hex(crypto.FromECDSA(issuerECPrivateKey))
	// We uses the EC Key to create a signature that works as a seed for generating the ED Key
	var edkeySeed [ed25519.SeedSize]byte
	sig, err := crypto.Sign(crypto.Keccak256([]byte("MetaBloxED25519")), issuerECPrivateKey)
	if err != nil {
		return err
	}
	edkeySeed = sha256.Sum256(sig)
	deterministicKey := ed25519.NewKeyFromSeed(edkeySeed[:])

	//newKey :=

	issuerEDPrivateKey = &deterministicKey

	err = InitIssuerDIDs(cfg.ChainList)
	if err != nil {
		return err
	}

	err = InitBoundedContracts(cfg.ChainList)
	if err != nil {
		return err
	}

	return nil
}

func keystoreToPrivateKey(privateKeyFile, password string) (*ecdsa.PrivateKey, error) {
	keystoreJSON, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read keyjson file failed: %s", err.Error())
	}
	key, err := keystore.DecryptKey(keystoreJSON, password)
	if err != nil {
		return nil, err
	}
	return key.PrivateKey, nil
}

func InitIssuerDIDs(chainList []string) error {

	issuerDIDs = make([]string, 0)
	for _, chainName := range chainList {
		_, ok := ChainName2IdMap[chainName]
		if !ok && chainName != "solana" {
			return ErrUnknownChainName
		}

		if chainName == "solana" {
			solPubKey, _ := issuerEDPrivateKey.Public().(ed25519.PublicKey)
			issuerDIDs = append(issuerDIDs, GenerateDIDString(&solPubKey, chainName))
		} else if chainName == "ethereum" {
			// Append 2 DIDs here, one is with the Chain Name and one without, both means on Ethereum
			issuerDIDs = append(issuerDIDs, GenerateDIDString(&issuerECPrivateKey.PublicKey, chainName))
			issuerDIDs = append(issuerDIDs, GenerateDIDString(&issuerECPrivateKey.PublicKey, ""))
		} else {
			issuerDIDs = append(issuerDIDs, GenerateDIDString(&issuerECPrivateKey.PublicKey, chainName))
		}

	}
	return nil
}

func parseAddress(s string) (string, string) {
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return s, "" // 没有冒号，全部为前部分，后部分空
	}
	return s[:idx], s[idx+1:]
}

func CheckIssuer(did string) bool {
	prefix, suffix := parseAddress(did)
	if common.IsHexAddress(suffix) {
		did = prefix + ":" + strings.ToLower(suffix)
	}
	for _, issuerDid := range issuerDIDs {
		if issuerDid == did {
			return true
		}
	}

	return false
}

func AddIssuer(did string) error {
	_, valid := PrepareDID(did)
	if !valid {
		return ErrInvalidDID
	}
	issuerDIDs = append(issuerDIDs, did)

	return nil
}

func RemoveIssuer(did string) error {
	for i, issuerDid := range issuerDIDs {
		if issuerDid == did {
			issuerDIDs = append(issuerDIDs[:i], issuerDIDs[i+1:]...)
			return nil
		}
	}

	return ErrUnknownIssuer
}

// create a credential proof using the provided verification method string
func CreateVCSecp256k1Proof(vm string) Secp256k1VCProof {
	vcProof := CreateSecp256k1VCProof()
	vcProof.Type = Secp256k1Sig
	vcProof.VerificationMethod = vm
	vcProof.JWSSignature = ""
	vcProof.Created = time.Now().UTC().Format(time.RFC3339)
	vcProof.ProofPurpose = PurposeAuth
	return *vcProof
}

func CreateVCEIP712Proof(vm string) EIP712VCProof {
	vcProof := CreateEIP712VCProof()
	vcProof.Type = EIP712Sig
	vcProof.VerificationMethod = vm
	vcProof.ProofValue = ""
	vcProof.Created = time.Now().UTC().Format(time.RFC3339)
	vcProof.ProofPurpose = PurposeAuth
	return *vcProof
}

func CreateVCEd25519Proof(vm string) Ed25519VCProof {
	vcProof := CreateEd25519VCProof()
	vcProof.Type = Ed25519Sig
	vcProof.VerificationMethod = vm
	vcProof.JWSSignature = ""
	vcProof.PublicKeyMultibase = ""
	vcProof.Created = time.Now().UTC().Format(time.RFC3339)
	vcProof.ProofPurpose = PurposeAuth
	return *vcProof
}

// convert issuance and expiration times of credential from db format to RFC3339
func ConvertTimesFromDBFormat(vc *VerifiableCredential) error {
	issuanceTime, err := time.Parse(time.RFC3339, vc.IssuanceDate)
	if err != nil {
		return err
	}
	vc.IssuanceDate = issuanceTime.Format(time.RFC3339)

	expirationTime, err := time.Parse(time.RFC3339, vc.ExpirationDate)
	if err != nil {
		return err
	}
	vc.ExpirationDate = expirationTime.Format(time.RFC3339)
	return nil
}

// convert issuance and expiration times of credential from RFC3339 to db format
func ConvertTimesToDBFormat(vc *VerifiableCredential) error {
	issuanceTime, err := time.Parse(time.RFC3339, vc.IssuanceDate)
	if err != nil {
		return err
	}
	vc.IssuanceDate = issuanceTime.Format(time.RFC3339)

	expirationTime, err := time.Parse(time.RFC3339, vc.ExpirationDate)
	if err != nil {
		return err
	}
	vc.ExpirationDate = expirationTime.Format(time.RFC3339)
	return nil
}

// Base function for creating VCs. Called by any function that creates a type of VC to initialize universal values
func CreateVC(issuerDocument *DIDDocument, proofType string) (*VerifiableCredential, error) {
	vcType := []string{TypeCredential}
	loc, _ := time.LoadLocation("UTC")
	expirationDate := time.Now().In(loc).AddDate(10, 0, 0).Format(time.RFC3339) //arbitrarily setting VCs to last for 10 years for the moment, can change when necessary
	description := ""

	var vcProof interface{}
	var context []string
	switch proofType {
	case Secp256k1Sig:
		vcProof = CreateVCSecp256k1Proof(issuerDocument.Authentication)
		context = []string{ContextSecp256k1, ContextCredential}
	case EIP712Sig:
		vcProof = CreateVCEIP712Proof(issuerDocument.Authentication)
		context = []string{ContextEIP712, ContextCredential}
	case Ed25519Sig:
		vcProof = CreateVCEd25519Proof(issuerDocument.Authentication)
		context = []string{ContextEd25519, ContextCredential}
	default:
		return nil, ErrUnknownProofType
	}

	newVC := NewVerifiableCredential(context, "0", vcType, issuerDocument.ID, time.Now().In(loc).Format(time.RFC3339), expirationDate, description, nil, vcProof, false)

	return newVC, nil
}

// convert credential to a JSON format. Currently unused
func VCToJson(vc *VerifiableCredential) ([]byte, error) {
	jsonVC, err := json.Marshal(vc)
	if err != nil {
		return nil, err
	}
	return jsonVC, nil
}

// convert JSON formatted credential to object. Currently unused
func JsonToVC(jsonVC []byte) (*VerifiableCredential, error) {
	vc := CreateVerifiableCredential()
	err := json.Unmarshal(jsonVC, vc)
	if err != nil {
		return nil, err
	}
	return vc, nil
}

// Need to make sure that the stated issuer of the VC actually created it (using the proof alongside the issuer's verification methods),
// as well as check that the issuer is a trusted source
func VerifyVC(vc *VerifiableCredential) (bool, error) {
	//issuer of VC must be the same issuer stored
	if !CheckIssuer(vc.Issuer) {
		return false, ErrUnknownIssuer
	}

	issuerChainName, err := GetChainNameFromDID(vc.Issuer)
	if err != nil {
		return false, err
	}
	bound, err := GetBoundedContract(issuerChainName)
	if err != nil {
		return false, err
	}

	resolutionMeta, issuerDoc, _ := Resolve(vc.Issuer, CreateResolutionOptions(), bound)
	if resolutionMeta.Error != "" {
		return false, errors.New(resolutionMeta.Error)
	}

	switch proof := vc.Proof.(type) {
	case Secp256k1VCProof:
		//get verification method from the issuer DID document which is listed in the vc proof
		targetVM, err := issuerDoc.RetrieveVerificationMethod(proof.VerificationMethod)
		if err != nil {
			return false, err
		}
		if targetVM.MethodType != Secp256k1Key { //vm must be the same type as the proof
			return false, ErrSecp256k1WrongVMType
		}
		return VerifySecp256k1VC(vc, targetVM.BlockchainAccountId)
	case EIP712VCProof:
		//get verification method from the issuer DID document which is listed in the vc proof
		targetVM, err := issuerDoc.RetrieveVerificationMethod(proof.VerificationMethod)
		if err != nil {
			return false, err
		}
		if targetVM.MethodType != Secp256k1Key { //vm must be the same type as the proof
			return false, ErrSecp256k1WrongVMType
		}
		return VerifyEIP712VC(vc, bound, targetVM.BlockchainAccountId)
	case Ed25519VCProof:
		//get verification method from the issuer DID document which is listed in the vc proof
		targetVM, err := issuerDoc.RetrieveVerificationMethod(proof.VerificationMethod)
		if err != nil {
			return false, err
		}
		if targetVM.MethodType != Ed25519Key { //vm must be the same type as the proof
			return false, ErrEd25519WrongVMType
		}
		return VerifyEd25519VC(vc)
	default:
		return false, ErrUnknownProofType
	}
}

// Verify that the provided public key matches the signature in the proof.
// Since we've made sure that the address in the issuer vm matches this public key,
// verifying the signature here proves that the signature was made with the issuer's private key
func VerifySecp256k1VC(vc *VerifiableCredential, expectedBlkID string) (bool, error) {
	copiedVC := *vc
	//have to make sure to remove the signature from the copy, as the original did not have a signature at the time the signature was generated
	proof, ok := copiedVC.Proof.(Secp256k1VCProof)
	if !ok {
		return false, ErrWrongProofType
	}
	jwsSignature := proof.JWSSignature
	proof.JWSSignature = ""
	copiedVC.Proof = proof

	vcBytes, err := ConvertVCToJWTPayload(copiedVC)
	if err != nil {
		return false, err
	}

	hashedVC := crypto.Keccak256(vcBytes)

	result, err := VerifyJWSSignature(jwsSignature, expectedBlkID, hashedVC[:])
	if err != nil {
		return false, err
	}
	return result, nil
}

func VerifyEIP712VC(credential *VerifiableCredential, bound *BoundedContract, expectedBlkID string) (bool, error) {

	EIP712DataHash, err := GenerateEIP712VCTypedDataHash(credential, *bound)
	if err != nil {
		return false, err
	}

	EIP712Proof, ok := credential.Proof.(EIP712VCProof)
	if !ok {
		return false, ErrWrongProofType
	}

	return VerifyEIP712Signature(EIP712Proof.ProofValue, expectedBlkID, EIP712DataHash.Bytes())
}

func VerifyEd25519VC(vc *VerifiableCredential) (bool, error) {
	copiedVC := *vc
	//have to make sure to remove the signature from the copy, as the original did not have a signature at the time the signature was generated
	proof, ok := copiedVC.Proof.(Ed25519VCProof)
	if !ok {
		return false, ErrWrongProofType
	}
	jwsSignature := proof.JWSSignature
	proof.JWSSignature = ""
	copiedVC.Proof = proof

	_, pubKey, err := multibase.Decode(proof.PublicKeyMultibase)
	if err != nil {
		return false, err
	}

	vcBytes, err := ConvertVCToJWTPayload(copiedVC)
	if err != nil {
		return false, err
	}
	hashedVC := sha512.Sum512(vcBytes)
	result, err := VerifyEd25519JWSSignature(jwsSignature, pubKey, hashedVC[:])
	if err != nil {
		return false, err
	}
	return result, nil
}

// convert credential to bytes so it can be hashed
func ConvertVCToBytes(vc VerifiableCredential) []byte {
	var convertedBytes []byte

	for _, item := range vc.Context {
		convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(item)}, []byte{})
	}

	for _, item := range vc.Type {
		convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(item)}, []byte{})
	}

	convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(vc.Issuer), []byte(vc.IssuanceDate), []byte(vc.ExpirationDate), []byte(vc.Description)}, []byte{})

	switch vc.Type[1] {
	case TypeWifi:
		m := &WifiAccessInfo{}
		err := mapstructure.Decode(vc.CredentialSubject, m)
		if err != nil {
			return nil
		}
		wifiAccessInfo := m
		convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(wifiAccessInfo.ID), []byte(wifiAccessInfo.Type)}, []byte{})
	case TypeMining:
		m := &MiningLicenseInfo{}
		err := mapstructure.Decode(vc.CredentialSubject, m)
		if err != nil {
			return nil
		}
		miningLicenseInfo := m
		convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(miningLicenseInfo.ID), []byte(miningLicenseInfo.Name), []byte(miningLicenseInfo.Model), []byte(miningLicenseInfo.Serial)}, []byte{})
	}

	return convertedBytes
}

func ConvertVCToJWTPayload(vc VerifiableCredential) (payloadByte []byte, err error) {

	var payload JwtCredentialPayload
	payloadByte = []byte{}

	payload.Iss = vc.Issuer
	payload.Jti = vc.ID
	expirationTime, err := time.Parse(time.RFC3339, vc.ExpirationDate)
	if err != nil {
		return payloadByte, err
	}
	payload.Exp = expirationTime.Unix()
	issuanceTime, err := time.Parse(time.RFC3339, vc.IssuanceDate)
	if err != nil {
		return payloadByte, err
	}
	payload.Iat = issuanceTime.Unix()
	payload.Vc.Context = vc.Context
	payload.Vc.Type = vc.Type
	payload.Vc.Description = vc.Description
	payload.Vc.Revoked = vc.Revoked
	payload.Vc.CredentialSubject = vc.CredentialSubject
	switch vc.Type[1] {
	case TypeWifi:
		m := &WifiAccessInfo{}
		err := mapstructure.Decode(vc.CredentialSubject, m)
		if err != nil {
			return payloadByte, err
		}
		payload.Vc.CredentialSubject = m
		payload.Sub = m.ID

	case TypeMining:
		m := &MiningLicenseInfo{}
		err := mapstructure.Decode(vc.CredentialSubject, m)
		if err != nil {
			return payloadByte, err
		}
		payload.Vc.CredentialSubject = m
		payload.Sub = m.ID
	default:
		return payloadByte, ErrUnknownCredentialType
	}

	payloadByte, err = canonicaljson.Marshal(payload)
	if err != nil {
		return payloadByte, err
	}

	return payloadByte, nil
}

func GenerateEIP712VCTypedDataHash(vc *VerifiableCredential, bound BoundedContract) (common.Hash, error) {

	domain := apitypes.TypedDataDomain{
		Name:              EIP712DomainName,
		Version:           EIP712DomainVersion,
		ChainId:           math.NewHexOrDecimal256(bound.ChainID.Int64()),
		VerifyingContract: bound.ContractAddr.Hex(),
	}

	types := apitypes.Types{
		"EIP712Domain": {
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
			{Name: "verifyingContract", Type: "address"},
		},
		"VerifiableCredential": {
			{Name: "@context", Type: "string[]"},
			{Name: "id", Type: "string"},
			{Name: "type", Type: "string[]"},
			{Name: "issuer", Type: "string"},
			{Name: "credentialSubjectData", Type: "bytes"},
			{Name: "issuanceDate", Type: "string"},
			{Name: "expirationDate", Type: "string"},
			{Name: "revoked", Type: "bool"},
		},
	}

	subjectBytes, err := canonicaljson.Marshal(vc.CredentialSubject)
	if err != nil {
		return common.Hash{0}, err
	}

	message := apitypes.TypedDataMessage{
		"@context":              vc.Context,
		"id":                    vc.ID,
		"type":                  vc.Type,
		"issuer":                vc.Issuer,
		"credentialSubjectData": crypto.Keccak256(subjectBytes),
		"issuanceDate":          vc.IssuanceDate,
		"expirationDate":        vc.ExpirationDate,
		"revoked":               vc.Revoked,
	}

	typedData := apitypes.TypedData{
		Types:       types,
		PrimaryType: EIP712DomainVCPrimayType,
		Domain:      domain,
		Message:     message,
	}

	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return common.Hash{0}, err
	}

	domainSeparator, err := typedData.HashStruct("EIP712Domain", domain.Map())
	if err != nil {
		return common.Hash{0}, err
	}

	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	hashBytes := crypto.Keccak256(rawData)
	hash := common.BytesToHash(hashBytes)

	return hash, nil
}
