package did

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

func TestCreateVCSecp256k1Proof(t *testing.T) {
	vm := "secp256k1"
	result := CreateVCSecp256k1Proof(vm)
	assert.NotNil(t, result)
}

func TestCreateVCEIP712Proof(t *testing.T) {
	vm := "eip712"
	result := CreateVCEIP712Proof(vm)
	assert.NotNil(t, result)
}

func TestConvertTimesFromDBFormat(t *testing.T) {
	vc := &VerifiableCredential{}
	err := ConvertTimesFromDBFormat(vc)
	assert.NoError(t, err)
}

func TestConvertTimesToDBFormat(t *testing.T) {
	vc := &VerifiableCredential{}
	err := ConvertTimesToDBFormat(vc)
	assert.NoError(t, err)
}

func TestCreateVC(t *testing.T) {
	issuerKey, _ := crypto.HexToECDSA("075a9987addcd8c2e709195533869b8b69eff2d61e345210b687bbc7ab8b66bb")
	presenterKey, _ := crypto.HexToECDSA("c62ee45278d87e5bdd8b7e895e9de16bfd1a3cbc9ddb7462bf9b30fc7502a3e8")
	bound, err := GetRegistryInstance(ChainName2ContractConfigMap[GoerliChainName])
	assert.NoError(t, err)
	doc := CreateDID(issuerKey, *bound)

	presenterAddress := crypto.PubkeyToAddress(presenterKey.PublicKey).Hex()
	presenterDid := fmt.Sprintf("did:metablox:gorli:%s", presenterAddress)

	testSubject := MiningLicenseInfo{
		CredentialID: "0",
		Serial:       "1234567890abcdef",
		ID:           presenterDid,
		Name:         "John Doe",
		Model:        "Antminer S19 Pro",
	}

	secp256VC, err := CreateVC(doc, Secp256k1Sig)
	assert.NoError(t, err)
	assert.NotNil(t, secp256VC)
	secp256VC.Type = append(secp256VC.Type, TypeMining)
	secp256VC.CredentialSubject = testSubject

	vcBytes, err := ConvertVCToJWTPayload(*secp256VC)
	assert.NoError(t, err)

	hashedVC := crypto.Keccak256(vcBytes)
	secp256Sig, err := CreateJWSSignature(issuerKey, hashedVC[:])
	assert.NoError(t, err)

	// Update the JWSSignature field of the Secp256k1VCProof struct
	proof := secp256VC.Proof.(Secp256k1VCProof)
	proof.JWSSignature = secp256Sig

	// Assign the updated struct back to the secp256VC.Proof field
	secp256VC.Proof = proof

	vcStr, err := json.Marshal(secp256VC)
	assert.NoError(t, err)
	assert.NotNil(t, vcStr)
}

func TestVCToJson(t *testing.T) {
	vc := &VerifiableCredential{}
	result, err := VCToJson(vc)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestJsonToVC(t *testing.T) {
	jsonVC := []byte(`{"id": "123"}`)
	result, err := JsonToVC(jsonVC)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}
