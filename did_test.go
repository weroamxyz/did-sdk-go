package did

import (
	"crypto/ecdsa"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

// ==================== Test Helpers ====================

func GenerateTestPrivKey() *ecdsa.PrivateKey {
	privKey, _ := crypto.ToECDSA(common.Hex2Bytes("dbbd9634560466ac9713e0cf10a575456c8b55388bce0c044f33fc6074dc5ae6"))
	return privKey
}

func GenerateTestDIDDocument() *DIDDocument {
	document := &DIDDocument{}
	document.Context = append(document.Context, ContextSecp256k1)
	document.Context = append(document.Context, ContextDID)
	document.ID = "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX"
	document.Created = "2022-03-31T12:53:19-07:00"
	document.Updated = "2022-03-31T12:53:19-07:00"
	document.Version = 1
	document.VerificationMethod = append(document.VerificationMethod, VerificationMethod{
		ID:                  "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification",
		MethodType:          "EcdsaSecp256k1RecoveryMethod2020",
		Controller:          "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
		BlockchainAccountId: "eip155:1666600000:0xBE1e1dB948CC1f441514aFb8924B67891f1c6889",
	})
	document.Authentication = "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification"
	return document
}

func GenerateTestResolvedDIDDocument() *DIDDocument {
	document := GenerateTestDIDDocument()
	document.VerificationMethod[0].BlockchainAccountId = "eip155:1666600000:0x25007b7AB5b0717F2Edd155F70746719e1862A52"
	return document
}

func GenerateTestSubjectInfo() *SubjectInfo {
	return NewSubjectInfo(
		"did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
		"John",
		"Jacobs",
		"Male",
		"Canada",
		"2022-03-22",
	)
}

func GenerateTestWifiAccessInfo() *WifiAccessInfo {
	return NewWifiAccessInfo(
		"sampleID",
		"did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
		"User",
	)
}

func GenerateTestMiningLicenseInfo() *MiningLicenseInfo {
	return NewMiningLicenseInfo(
		"1",
		"did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
		"TestName",
		"TestModel",
		"TestSerial",
	)
}

func GenerateTestVC() *VerifiableCredential {
	vcProof := NewVCProof(
		Secp256k1Sig,
		"2022-03-31T12:53:19-07:00",
		"did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification",
		PurposeAuth,
		"eyJhbGciOiJFUzI1NiJ9..IklF2w-lM8CDeBBxKjoAEf_t22jngbmtI9n7hd_47zE_d2Qcj2kwHBHwHFVOTL3nqTrkycVdZmWtgw3M6tMqoA",
	)

	subjectInfo := GenerateTestSubjectInfo()

	return NewVerifiableCredential(
		[]string{ContextCredential, ContextSecp256k1},
		"http://metablox.com/credentials/1",
		[]string{TypeCredential, "PermanentResidentCard"},
		"did:metablox:sampleIssuer",
		"2022-03-31T12:53:19-07:00",
		"2032-03-31T12:53:19-07:00",
		"Government of Example Permanent Resident Card",
		*subjectInfo,
		*vcProof,
		false,
	)
}

func GenerateTestWifiAccessVC() *VerifiableCredential {
	vcProof := NewVCProof(
		Secp256k1Sig,
		"2022-03-31T12:53:19-07:00",
		"did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification",
		PurposeAuth,
		"eyJhbGciOiJFUzI1NiJ9..SnGaW3ya8MM-DXbRSFXWHM_R7Vg_3u_u1OxEfxvwXzQWNRmmC5noWvleSEM3iQdofm7towbpJ6nABQs9e1-OvA",
	)

	wifiAccessInfo := GenerateTestWifiAccessInfo()

	return NewVerifiableCredential(
		[]string{ContextSecp256k1, ContextCredential},
		"http://metablox.com/credentials/1",
		[]string{TypeCredential, TypeWifi},
		"did:metablox:sampleIssuer",
		"2022-03-31T12:53:19-07:00",
		"2032-03-31T12:53:19-07:00",
		"Example Wifi Access Credential",
		*wifiAccessInfo,
		*vcProof,
		false,
	)
}

func GenerateTestMiningLicenseVC() *VerifiableCredential {
	vcProof := NewVCProof(
		Secp256k1Sig,
		"2022-03-31T12:53:19-07:00",
		"did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification",
		PurposeAuth,
		"eyJhbGciOiJFUzI1NiJ9..SnGaW3ya8MM-DXbRSFXWHM_R7Vg_3u_u1OxEfxvwXzQWNRmmC5noWvleSEM3iQdofm7towbpJ6nABQs9e1-OvA",
	)

	miningLicenseInfo := GenerateTestMiningLicenseInfo()

	return NewVerifiableCredential(
		[]string{ContextSecp256k1, ContextCredential},
		"http://metablox.com/credentials/1",
		[]string{TypeCredential, TypeMining},
		"did:metablox:sampleIssuer",
		"2022-03-31T12:53:19-07:00",
		"2032-03-31T12:53:19-07:00",
		"Example Mining License Credential",
		*miningLicenseInfo,
		*vcProof,
		false,
	)
}

func GenerateTestPresentation() *VerifiablePresentation {
	vpProof := NewVPProof(
		Secp256k1Sig,
		"2022-03-31T12:53:19-07:00",
		"did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification",
		PurposeAuth,
		"eyJhbGciOiJFUzI1NiJ9..PKCD7kcMsRLD2hYGvkdvsYxpIT-krrkYs4VZmjqYOZ4gtUEYkKpZKW8cUUSHmF0Tb4IxkGaq3b4H__3HiQNGyw",
		"sampleNonce",
	)

	return NewPresentation(
		[]string{ContextSecp256k1, ContextCredential},
		[]string{"VerifiablePresentation"},
		[]VerifiableCredential{*GenerateTestVC()},
		"did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
		*vpProof,
	)
}

func GenerateTestWifiAccessPresentation() *VerifiablePresentation {
	vpProof := NewVPProof(
		Secp256k1Sig,
		"2022-03-31T12:53:19-07:00",
		"did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification",
		PurposeAuth,
		"eyJhbGciOiJFUzI1NiJ9..bmj6KhHcBkLOHgAZrLqgweE-StyBXvvj6bmZqC6TqiYVtC_tXf076xDAAXzmx160dAqivTzgX-943ZU-VWXDqw",
		"123456",
	)

	return NewPresentation(
		[]string{ContextCredential, ContextSecp256k1},
		[]string{"VerifiablePresentation"},
		[]VerifiableCredential{*GenerateTestWifiAccessVC()},
		"did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
		*vpProof,
	)
}

// ==================== DID Tests ====================

func TestGenerateDIDString(t *testing.T) {
	testKey, err := crypto.HexToECDSA("c62ee45278d87e5bdd8b7e895e9de16bfd1a3cbc9ddb7462bf9b30fc7502a3e8")
	testAddr := crypto.PubkeyToAddress(testKey.PublicKey)
	if err != nil {
		t.Errorf("GenerateDIDString failed: %v", err)
	}
	network := "testnet"

	didString := GenerateDIDString(&testKey.PublicKey, network)
	splitDID := strings.Split(didString, ":")

	if len(didString) == 0 {
		t.Errorf("GenerateDIDString failed: expected non-empty DID string, got empty string")
	}
	if len(splitDID) != 4 {
		t.Errorf("GenerateDIDString failed: expected 4 sections, got %d", len(splitDID))
	}
	if splitDID[0] != "did" || splitDID[1] != "metablox" || splitDID[2] != network || splitDID[3] != testAddr.String() {
		t.Errorf("GenerateDIDString failed: expected ['did', 'metablox', network, address], got %v", splitDID)
	}

}

func TestValidateDID(t *testing.T) {
	// Use a valid Ethereum address format for testing
	validDID := []string{"did", "metablox", "0xBE1e1dB948CC1f441514aFb8924B67891f1c6889"}
	invalidDID := []string{"did", "metablox"}

	err := ValidateDID(validDID)
	if err != nil {
		t.Errorf("ValidateDID failed: expected valid DID, got error: %v", err)
	}

	err = ValidateDID(invalidDID)
	if err == nil {
		t.Errorf("ValidateDID failed: expected error for invalid DID, got nil")
	}
}

func TestSplitDIDString(t *testing.T) {
	didString := "did:metablox:1234567890"

	splitDID := SplitDIDString(didString)

	if len(splitDID) != 3 {
		t.Errorf("SplitDIDString failed: expected 3 sections, got %d", len(splitDID))
	}

	if splitDID[0] != "did" || splitDID[1] != "metablox" || splitDID[2] != "1234567890" {
		t.Errorf("SplitDIDString failed: expected ['did', 'metablox', '1234567890'], got %v", splitDID)
	}
}

func TestPrepareDID(t *testing.T) {
	testKey, _ := crypto.HexToECDSA("c62ee45278d87e5bdd8b7e895e9de16bfd1a3cbc9ddb7462bf9b30fc7502a3e8")
	testAddr := crypto.PubkeyToAddress(testKey.PublicKey)
	validDID := "did:metablox:testnet:" + testAddr.String()
	invalidDID := "did:metablox"

	validSections, valid := PrepareDID(validDID)
	invalidSections, invalid := PrepareDID(invalidDID)

	if !valid {
		t.Errorf("PrepareDID failed: expected valid DID, got invalid")
	}

	if validSections[0] != "did" || validSections[1] != "metablox" || validSections[2] != "testnet" || validSections[3] != testAddr.String() {
		t.Errorf("PrepareDID failed: expected ['did', 'metablox', '1234567890'], got %v", validSections)
	}

	if invalid {
		t.Errorf("PrepareDID failed: expected invalid DID, got valid, %v", invalidSections)
	}
}

// ==================== Credential Tests ====================

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
	vc := &VerifiableCredential{
		IssuanceDate:   "2022-03-31T12:53:19-07:00",
		ExpirationDate: "2032-03-31T12:53:19-07:00",
	}
	err := ConvertTimesFromDBFormat(vc)
	assert.NoError(t, err)
}

func TestConvertTimesToDBFormat(t *testing.T) {
	vc := &VerifiableCredential{
		IssuanceDate:   "2022-03-31T12:53:19-07:00",
		ExpirationDate: "2032-03-31T12:53:19-07:00",
	}
	err := ConvertTimesToDBFormat(vc)
	assert.NoError(t, err)
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

// ==================== Presentation Tests ====================

func TestCreateVPSecp256k1Proof(t *testing.T) {
	vm := "test_vm"
	nonce := "test_nonce"

	proof := CreateVPSecp256k1Proof(vm, nonce)

	assert.NotNil(t, proof)
}

func TestCreateVPEIP712Proof(t *testing.T) {
	vm := "test_vm"
	nonce := "test_nonce"

	proof := CreateVPEIP712Proof(vm, nonce)

	assert.NotNil(t, proof)
}

// ==================== Proof Parsing Tests ====================

func TestParseVCProof_Secp256k1(t *testing.T) {
	vcJSON := `{
		"@context": ["https://www.w3.org/2018/credentials/v1"],
		"id": "test-vc",
		"type": ["VerifiableCredential"],
		"issuer": "did:metablox:harmony:0x123",
		"issuanceDate": "2024-01-01T00:00:00Z",
		"expirationDate": "2034-01-01T00:00:00Z",
		"credentialSubject": {},
		"proof": {
			"type": "EcdsaSecp256k1Signature2019",
			"created": "2024-01-01T00:00:00Z",
			"verificationMethod": "did:metablox:harmony:0x123#controller",
			"proofPurpose": "Authentication",
			"jws": "test-signature"
		}
	}`

	var vc VerifiableCredential
	err := json.Unmarshal([]byte(vcJSON), &vc)
	assert.NoError(t, err)

	// Before parsing, proof is a map
	_, isMap := vc.Proof.(map[string]interface{})
	assert.True(t, isMap, "proof should be a map before parsing")

	// Parse the proof
	err = ParseVCProof(&vc)
	assert.NoError(t, err)

	// After parsing, proof should be typed
	proof, isTyped := vc.Proof.(Secp256k1VCProof)
	assert.True(t, isTyped, "proof should be Secp256k1VCProof after parsing")
	assert.Equal(t, Secp256k1Sig, proof.Type)
	assert.Equal(t, "test-signature", proof.JWSSignature)
}

func TestParseVCProof_EIP712(t *testing.T) {
	vcJSON := `{
		"@context": ["https://www.w3.org/2018/credentials/v1"],
		"id": "test-vc",
		"type": ["VerifiableCredential"],
		"issuer": "did:metablox:harmony:0x123",
		"issuanceDate": "2024-01-01T00:00:00Z",
		"expirationDate": "2034-01-01T00:00:00Z",
		"credentialSubject": {},
		"proof": {
			"type": "Eip712Signature2021",
			"created": "2024-01-01T00:00:00Z",
			"verificationMethod": "did:metablox:harmony:0x123#controller",
			"proofPurpose": "Authentication",
			"proofValue": "test-proof-value"
		}
	}`

	var vc VerifiableCredential
	err := json.Unmarshal([]byte(vcJSON), &vc)
	assert.NoError(t, err)

	err = ParseVCProof(&vc)
	assert.NoError(t, err)

	proof, isTyped := vc.Proof.(EIP712VCProof)
	assert.True(t, isTyped, "proof should be EIP712VCProof after parsing")
	assert.Equal(t, EIP712Sig, proof.Type)
	assert.Equal(t, "test-proof-value", proof.ProofValue)
}

func TestParseVCProof_AlreadyTyped(t *testing.T) {
	vc := &VerifiableCredential{
		Proof: Secp256k1VCProof{
			BaseProof: BaseProof{
				Type: Secp256k1Sig,
			},
			JWSSignature: "existing-sig",
		},
	}

	// Should not error when proof is already typed
	err := ParseVCProof(vc)
	assert.NoError(t, err)

	// Proof should remain unchanged
	proof, isTyped := vc.Proof.(Secp256k1VCProof)
	assert.True(t, isTyped)
	assert.Equal(t, "existing-sig", proof.JWSSignature)
}

func TestParseVPProof_WithVCs(t *testing.T) {
	vpJSON := `{
		"@context": ["https://www.w3.org/2018/credentials/v1"],
		"type": ["VerifiablePresentation"],
		"holder": "did:metablox:harmony:0x456",
		"verifiableCredential": [{
			"@context": ["https://www.w3.org/2018/credentials/v1"],
			"id": "test-vc",
			"type": ["VerifiableCredential"],
			"issuer": "did:metablox:harmony:0x123",
			"issuanceDate": "2024-01-01T00:00:00Z",
			"expirationDate": "2034-01-01T00:00:00Z",
			"credentialSubject": {},
			"proof": {
				"type": "EcdsaSecp256k1Signature2019",
				"created": "2024-01-01T00:00:00Z",
				"verificationMethod": "did:metablox:harmony:0x123#controller",
				"proofPurpose": "Authentication",
				"jws": "vc-signature"
			}
		}],
		"proof": {
			"type": "EcdsaSecp256k1Signature2019",
			"created": "2024-01-01T00:00:00Z",
			"verificationMethod": "did:metablox:harmony:0x456#controller",
			"proofPurpose": "Authentication",
			"jws": "vp-signature",
			"nonce": "test-nonce"
		}
	}`

	var vp VerifiablePresentation
	err := json.Unmarshal([]byte(vpJSON), &vp)
	assert.NoError(t, err)

	err = ParseVPProof(&vp)
	assert.NoError(t, err)

	// Check VP proof
	vpProof, isTyped := vp.Proof.(Secp256k1VPProof)
	assert.True(t, isTyped, "VP proof should be Secp256k1VPProof after parsing")
	assert.Equal(t, "vp-signature", vpProof.JWSSignature)
	assert.Equal(t, "test-nonce", vpProof.Nonce)

	// Check VC proof inside VP
	assert.Len(t, vp.VerifiableCredential, 1)
	vcProof, isTyped := vp.VerifiableCredential[0].Proof.(Secp256k1VCProof)
	assert.True(t, isTyped, "VC proof should be Secp256k1VCProof after parsing")
	assert.Equal(t, "vc-signature", vcProof.JWSSignature)
}

func TestGetVCProofType(t *testing.T) {
	// Typed proof
	vc1 := &VerifiableCredential{
		Proof: Secp256k1VCProof{
			BaseProof: BaseProof{Type: Secp256k1Sig},
		},
	}
	assert.Equal(t, Secp256k1Sig, GetVCProofType(vc1))

	// Map proof
	vc2 := &VerifiableCredential{
		Proof: map[string]interface{}{"type": EIP712Sig},
	}
	assert.Equal(t, EIP712Sig, GetVCProofType(vc2))

	// Unknown proof
	vc3 := &VerifiableCredential{
		Proof: "invalid",
	}
	assert.Equal(t, "", GetVCProofType(vc3))
}

func TestGetVCProofVerificationMethod(t *testing.T) {
	vm := "did:metablox:harmony:0x123#controller"

	// Typed proof
	vc1 := &VerifiableCredential{
		Proof: Secp256k1VCProof{
			BaseProof: BaseProof{VerificationMethod: vm},
		},
	}
	assert.Equal(t, vm, GetVCProofVerificationMethod(vc1))

	// Map proof
	vc2 := &VerifiableCredential{
		Proof: map[string]interface{}{"verificationMethod": vm},
	}
	assert.Equal(t, vm, GetVCProofVerificationMethod(vc2))
}

// TestChainMaps verifies chain ID/name mappings are correct
func TestChainMaps(t *testing.T) {
	// Verify harmony chain
	assert.Equal(t, 1666600000, ChainName2IdMap[HarmonyChainName])
	assert.Equal(t, HarmonyChainName, ChainId2NameMap[1666600000])

	// Verify solana chain
	assert.Equal(t, 245022926, ChainName2IdMap[SolanaChainName])
	assert.Equal(t, SolanaChainName, ChainId2NameMap[245022926])

	// Verify ethereum chain (for DID parsing default)
	assert.Equal(t, 1, ChainName2IdMap[EthereumChainName])
	assert.Equal(t, EthereumChainName, ChainId2NameMap[1])
}

// TestGetContractConfig verifies contract config retrieval
func TestGetContractConfig(t *testing.T) {
	// Harmony with default RPC
	cfg, ok := getContractConfig(HarmonyChainName, "")
	assert.True(t, ok)
	assert.Equal(t, HarmonyChainName, cfg.ChainName)
	assert.Equal(t, HarmonyContractAddr, cfg.ContractAddr)
	assert.Equal(t, DefaultHarmonyRPCURL, cfg.RpcUrl)

	// Harmony with custom RPC
	customRPC := "https://custom-harmony.example.com"
	cfg, ok = getContractConfig(HarmonyChainName, customRPC)
	assert.True(t, ok)
	assert.Equal(t, customRPC, cfg.RpcUrl)

	// Solana with default RPC
	cfg, ok = getContractConfig(SolanaChainName, "")
	assert.True(t, ok)
	assert.Equal(t, SolanaChainName, cfg.ChainName)
	assert.Equal(t, SolanaContractAddr, cfg.ContractAddr)

	// Ethereum - no contract config
	_, ok = getContractConfig(EthereumChainName, "")
	assert.False(t, ok, "Ethereum should not have contract config")

	// Unknown chain
	_, ok = getContractConfig("unknown", "")
	assert.False(t, ok)
}
