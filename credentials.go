package did

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MetaBloxIO/did-sdk-go/registry"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/mitchellh/mapstructure"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
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
	issuerDID = GenerateDIDString(issuerPrivateKey)
	issuerChainId = cfg.ChainId
	return nil
}

func keystoreToPrivateKey(privateKeyFile, password string) (*ecdsa.PrivateKey, error) {
	keystoreJSON, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read keyjson file failed：%s", err.Error())
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
func CreateProof(vm string) VCProof {
	vcProof := CreateVCProof()
	vcProof.Type = Secp256k1Sig
	vcProof.VerificationMethod = vm
	vcProof.JWSSignature = ""
	vcProof.Created = time.Now().UTC().Format(time.RFC3339)
	vcProof.ProofPurpose = PurposeAuth
	vcProof.PublicKeyString = crypto.FromECDSAPub(&issuerPrivateKey.PublicKey)
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
func CreateVC(issuerDocument *DIDDocument) (*VerifiableCredential, error) {
	context := []string{ContextSecp256k1, ContextCredential}
	vcType := []string{TypeCredential}
	loc, _ := time.LoadLocation("UTC")
	expirationDate := time.Now().In(loc).AddDate(10, 0, 0).Format(time.RFC3339) //arbitrarily setting VCs to last for 10 years for the moment, can change when necessary
	description := ""

	vcProof := CreateProof(issuerDocument.Authentication)

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
func VerifyVC(vc *VerifiableCredential, registry *registry.Registry) (bool, error) {
	if vc.Issuer != issuerDID { //issuer of VC must be the same issuer stored here
		return false, ErrUnknownIssuer
	}

	resolutionMeta, issuerDoc, _ := Resolve(vc.Issuer, CreateResolutionOptions(), registry)
	if resolutionMeta.Error != "" {
		return false, errors.New(resolutionMeta.Error)
	}

	//get verification method from the issuer DID document which is listed in the vc proof
	targetVM, err := issuerDoc.RetrieveVerificationMethod(vc.Proof.VerificationMethod)
	if err != nil {
		return false, err
	}

	//get public key stored in the vc proof
	publicKey, err := crypto.UnmarshalPubkey(vc.Proof.PublicKeyString)
	if err != nil {
		return false, err
	}

	//currently only support EcdsaSecp256k1Signature2019, but it's possible we could introduce more
	switch vc.Proof.Type {
	case Secp256k1Sig:
		if targetVM.MethodType != Secp256k1Key { //vm must be the same type as the proof
			return false, ErrSecp256k1WrongVMType
		}

		success := CompareAddresses(targetVM, publicKey) //vm must have the address that matches the proof's public key
		if !success {
			return false, ErrWrongAddress
		}

		return VerifyVCSecp256k1(vc, publicKey)
	default:
		return false, ErrUnknownProofType
	}
}

// Verify that the provided public key matches the signature in the proof.
// Since we've made sure that the address in the issuer vm matches this public key,
// verifying the signature here proves that the signature was made with the issuer's private key
func VerifyVCSecp256k1(vc *VerifiableCredential, pubKey *ecdsa.PublicKey) (bool, error) {
	copiedVC := *vc
	//have to make sure to remove the signature from the copy, as the original did not have a signature at the time the signature was generated
	copiedVC.Proof.JWSSignature = ""
	hashedVC := sha256.Sum256(ConvertVCToBytes(copiedVC))

	result, err := VerifyJWSSignature(vc.Proof.JWSSignature, pubKey, hashedVC[:])
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

	convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(vc.Proof.Type), []byte(vc.Proof.Created), []byte(vc.Proof.VerificationMethod), []byte(vc.Proof.ProofPurpose), []byte(vc.Proof.JWSSignature), vc.Proof.PublicKeyString}, []byte{})
	return convertedBytes
}
