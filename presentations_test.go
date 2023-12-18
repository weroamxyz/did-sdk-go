package did

import (
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

func TestCreateVPSecp256k1Proof(t *testing.T) {
	vm := "test_vm"
	nonce := "test_nonce"

	proof := CreateVPSecp256k1Proof(vm, nonce)

	assert.NotNil(t, proof)
	// Add more assertions here
}

func TestCreateVPEIP712Proof(t *testing.T) {
	vm := "test_vm"
	nonce := "test_nonce"

	proof := CreateVPEIP712Proof(vm, nonce)

	assert.NotNil(t, proof)
	// Add more assertions here
}

func TestCreatePresentation(t *testing.T) {
	presenterKey, _ := crypto.HexToECDSA("c62ee45278d87e5bdd8b7e895e9de16bfd1a3cbc9ddb7462bf9b30fc7502a3e8")
	bound, err := GetRegistryInstance(GoerliNetwork)
	assert.NoError(t, err)

	presenterDoc := CreateDID(presenterKey, *bound)

	vcStr :=
		`{
		"@context": [
		  "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#",
		  "https://www.w3.org/2018/credentials/v1"
		],
		"id": "0",
		"type": [
		  "VerifiableCredential",
		  "MiningLicense"
		],
		"issuer": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A",
		"issuanceDate": "2023-12-12T15:52:35Z",
		"expirationDate": "2033-12-12T15:52:35Z",
		"description": "",
		"credentialSubject": {
		  "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
		  "name": "John Doe",
		  "model": "Antminer S19 Pro",
		  "serial": "1234567890abcdef"
		},
		"proof": {
		  "type": "EcdsaSecp256k1Signature2019",
		  "created": "2023-12-12T15:52:35Z",
		  "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
		  "proofPurpose": "Authentication",
		  "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..d2n70u-3cJKZ4EfmHe2gymfpYYFZdx0cQTzyx36rFa83HKROil2xowySmNqpftVFECDX-0dz0-v2QEmuPobMARw"
		},
		"revoked": false
	  }`

	var vc VerifiableCredential
	err = json.Unmarshal([]byte(vcStr), &vc)
	assert.NoError(t, err)

	vp, err := CreatePresentation([]VerifiableCredential{vc}, *presenterDoc, presenterKey, "lastBlkNum_audienceAddress", Secp256k1Sig, bound)

	assert.NoError(t, err)
	assert.NotNil(t, vp)
	// Add more assertions here
}

func TestVerifyVP(t *testing.T) {
	bound, err := GetRegistryInstance(GoerliNetwork)
	assert.NoError(t, err)
	vpStr :=
		`{
		"@context": [
		  "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#",
		  "https://www.w3.org/2018/credentials/v1"
		],
		"type": [
		  "VerifiablePresentation"
		],
		"verifiableCredential": [
		  {
			"@context": [
			  "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#",
			  "https://www.w3.org/2018/credentials/v1"
			],
			"id": "0",
			"type": [
			  "VerifiableCredential",
			  "MiningLicense"
			],
			"issuer": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A",
			"issuanceDate": "2023-12-12T15:52:35Z",
			"expirationDate": "2033-12-12T15:52:35Z",
			"description": "",
			"credentialSubject": {
			  "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
			  "name": "John Doe",
			  "model": "Antminer S19 Pro",
			  "serial": "1234567890abcdef"
			},
			"proof": {
			  "type": "EcdsaSecp256k1Signature2019",
			  "created": "2023-12-12T15:52:35Z",
			  "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
			  "proofPurpose": "Authentication",
			  "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..d2n70u-3cJKZ4EfmHe2gymfpYYFZdx0cQTzyx36rFa83HKROil2xowySmNqpftVFECDX-0dz0-v2QEmuPobMARw"
			},
			"revoked": false
		  }
		],
		"holder": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665",
		"proof": {
		  "type": "EcdsaSecp256k1Signature2019",
		  "created": "2023-12-12T15:57:16Z",
		  "verificationMethod": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665#controller",
		  "proofPurpose": "Authentication",
		  "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..wJEM8P7hHaFYi8OQ5A5RFvMfL7j2XrRTHzq-sIUKNQ8xsG3U7FcAtgT84RiqxVf8Cs2i0t7Bme6crWrj5U6viRw",
		  "nonce": "lastBlkNum_audienceAddress"
		}
	  }`
	var vp VerifiablePresentation
	err = json.Unmarshal([]byte(vpStr), &vp)
	assert.NoError(t, err)
	assert.NotNil(t, vp)

	result, err := VerifyVP(&vp, bound)
	assert.NoError(t, err)
	assert.True(t, result)
}
