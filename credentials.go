package did

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/gibson042/canonicaljson-go"
	"github.com/mitchellh/mapstructure"
)

var issuerDID string
var issuerPrivateKey *ecdsa.PrivateKey
var issuerChainId *big.Int

func GetIssuerDid() string {
	return issuerDID
}
func GetIssuerPrivateKey() *ecdsa.PrivateKey {
	return issuerPrivateKey
}
func GetIssuerChainId() *big.Int {
	return issuerChainId
}

// All credential ids use a format of this value plus a number. ex. 'http://metablox.com/credentials/5'
// Only the number is stored in the db as the ID; the full string is only used in formal credentials
const BaseIDString = "https://metablox.io/credentials/"

type Config struct {
	Passphrase string   `json:"passphrase"`
	Keystore   string   `json:"keystore"`
	ChainId    *big.Int `json:"chainId"`
}

func Init(cfg *Config) error {
	var err error
	issuerPrivateKey, err = keystoreToPrivateKey(cfg.Keystore, cfg.Passphrase)
	if err != nil {
		return err
	}
	issuerDID = GenerateDIDString(&issuerPrivateKey.PublicKey, "0x"+issuerChainId.Text(16))
	issuerChainId = cfg.ChainId
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
	//privKey := hex.EncodeToString(unlockedKey.PrivateKey.D.Bytes())
	//addr := crypto.PubkeyToAddress(unlockedKey.PrivateKey.PublicKey)
	return key.PrivateKey, nil
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
func VerifyVC(vc *VerifiableCredential, bound *BoundedContract) (bool, error) {
	if vc.Issuer != issuerDID { //issuer of VC must be the same issuer stored here
		return false, ErrUnknownIssuer
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

	hashedVC := sha256.Sum256(vcBytes)

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
