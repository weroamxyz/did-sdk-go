package did

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/gibson042/canonicaljson-go"
	"github.com/mitchellh/mapstructure"
	"github.com/multiformats/go-multibase"
)

// ====================
// Proof Parsing
// ====================

// ParseVCProof converts a map[string]interface{} proof (from JSON unmarshaling)
// to the appropriate typed proof struct.
func ParseVCProof(vc *VerifiableCredential) error {
	proofDict, ok := vc.Proof.(map[string]interface{})
	if !ok {
		return nil
	}

	proofStr, err := json.Marshal(proofDict)
	if err != nil {
		return ErrUnknownProofType
	}

	proofType, ok := proofDict["type"].(string)
	if !ok {
		return ErrUnknownProofType
	}

	switch proofType {
	case Secp256k1Sig:
		var proof Secp256k1VCProof
		if err := json.Unmarshal(proofStr, &proof); err != nil {
			return ErrUnknownProofType
		}
		vc.Proof = proof
	case EIP712Sig:
		var proof EIP712VCProof
		if err := json.Unmarshal(proofStr, &proof); err != nil {
			return ErrUnknownProofType
		}
		vc.Proof = proof
	case Ed25519Sig:
		var proof Ed25519VCProof
		if err := json.Unmarshal(proofStr, &proof); err != nil {
			return ErrUnknownProofType
		}
		vc.Proof = proof
	default:
		return ErrUnknownProofType
	}

	return nil
}

// ParseVPProof converts a map[string]interface{} proof (from JSON unmarshaling)
// to the appropriate typed proof struct. It also parses all contained VC proofs.
func ParseVPProof(vp *VerifiablePresentation) error {
	proofDict, ok := vp.Proof.(map[string]interface{})
	if !ok {
		for idx := range vp.VerifiableCredential {
			if err := ParseVCProof(&vp.VerifiableCredential[idx]); err != nil {
				return err
			}
		}
		return nil
	}

	proofStr, err := json.Marshal(proofDict)
	if err != nil {
		return ErrUnknownProofType
	}

	proofType, ok := proofDict["type"].(string)
	if !ok {
		return ErrUnknownProofType
	}

	switch proofType {
	case Secp256k1Sig:
		var proof Secp256k1VPProof
		if err := json.Unmarshal(proofStr, &proof); err != nil {
			return ErrUnknownProofType
		}
		vp.Proof = proof
	case EIP712Sig:
		var proof EIP712VPProof
		if err := json.Unmarshal(proofStr, &proof); err != nil {
			return ErrUnknownProofType
		}
		vp.Proof = proof
	case Ed25519Sig:
		var proof Ed25519VPProof
		if err := json.Unmarshal(proofStr, &proof); err != nil {
			return ErrUnknownProofType
		}
		vp.Proof = proof
	default:
		return ErrUnknownProofType
	}

	for idx := range vp.VerifiableCredential {
		if err := ParseVCProof(&vp.VerifiableCredential[idx]); err != nil {
			return err
		}
	}

	return nil
}

// GetVCProofType returns the proof type string from a VC.
func GetVCProofType(vc *VerifiableCredential) string {
	switch proof := vc.Proof.(type) {
	case Secp256k1VCProof:
		return proof.Type
	case EIP712VCProof:
		return proof.Type
	case Ed25519VCProof:
		return proof.Type
	case map[string]interface{}:
		if t, ok := proof["type"].(string); ok {
			return t
		}
	}
	return ""
}

// GetVPProofType returns the proof type string from a VP.
func GetVPProofType(vp *VerifiablePresentation) string {
	switch proof := vp.Proof.(type) {
	case Secp256k1VPProof:
		return proof.Type
	case EIP712VPProof:
		return proof.Type
	case Ed25519VPProof:
		return proof.Type
	case map[string]interface{}:
		if t, ok := proof["type"].(string); ok {
			return t
		}
	}
	return ""
}

// GetVCProofVerificationMethod returns the verification method from a VC proof.
func GetVCProofVerificationMethod(vc *VerifiableCredential) string {
	switch proof := vc.Proof.(type) {
	case Secp256k1VCProof:
		return proof.VerificationMethod
	case EIP712VCProof:
		return proof.VerificationMethod
	case Ed25519VCProof:
		return proof.VerificationMethod
	case map[string]interface{}:
		if vm, ok := proof["verificationMethod"].(string); ok {
			return vm
		}
	}
	return ""
}

// GetVPProofVerificationMethod returns the verification method from a VP proof.
func GetVPProofVerificationMethod(vp *VerifiablePresentation) string {
	switch proof := vp.Proof.(type) {
	case Secp256k1VPProof:
		return proof.VerificationMethod
	case EIP712VPProof:
		return proof.VerificationMethod
	case Ed25519VPProof:
		return proof.VerificationMethod
	case map[string]interface{}:
		if vm, ok := proof["verificationMethod"].(string); ok {
			return vm
		}
	}
	return ""
}

// ====================
// VC Operations
// ====================

func parseAddress(s string) (string, string, bool) {
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return s, "", false
	}
	return s[:idx], s[idx+1:], common.IsHexAddress(s[idx+1:])
}

// CreateVCSecp256k1Proof creates a credential proof using secp256k1 signature.
func CreateVCSecp256k1Proof(vm string) Secp256k1VCProof {
	return Secp256k1VCProof{
		BaseProof: BaseProof{
			Type:               Secp256k1Sig,
			VerificationMethod: vm,
			Created:            time.Now().UTC().Format(time.RFC3339),
			ProofPurpose:       PurposeAuth,
		},
		JWSSignature: "",
	}
}

// CreateVCEIP712Proof creates a credential proof using EIP712 signature.
func CreateVCEIP712Proof(vm string) EIP712VCProof {
	return EIP712VCProof{
		BaseProof: BaseProof{
			Type:               EIP712Sig,
			VerificationMethod: vm,
			Created:            time.Now().UTC().Format(time.RFC3339),
			ProofPurpose:       PurposeAuth,
		},
		ProofValue: "",
	}
}

// CreateVCEd25519Proof creates a credential proof using Ed25519 signature.
func CreateVCEd25519Proof(vm string) Ed25519VCProof {
	return Ed25519VCProof{
		BaseProof: BaseProof{
			Type:               Ed25519Sig,
			VerificationMethod: vm,
			Created:            time.Now().UTC().Format(time.RFC3339),
			ProofPurpose:       PurposeAuth,
		},
		JWSSignature:       "",
		PublicKeyMultibase: "",
	}
}

// ValidateAndNormalizeVCTimes validates that the VC's issuance and expiration dates
// are in RFC3339 format and normalizes them.
func ValidateAndNormalizeVCTimes(vc *VerifiableCredential) error {
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

// ConvertTimesFromDBFormat validates and normalizes VC times.
// Deprecated: Use ValidateAndNormalizeVCTimes instead.
func ConvertTimesFromDBFormat(vc *VerifiableCredential) error {
	return ValidateAndNormalizeVCTimes(vc)
}

// ConvertTimesToDBFormat validates and normalizes VC times.
// Deprecated: Use ValidateAndNormalizeVCTimes instead.
func ConvertTimesToDBFormat(vc *VerifiableCredential) error {
	return ValidateAndNormalizeVCTimes(vc)
}

// CreateVC creates a base VC with the specified proof type.
func CreateVC(issuerDocument *DIDDocument, proofType string) (*VerifiableCredential, error) {
	vcType := []string{TypeCredential}
	loc, _ := time.LoadLocation("UTC")
	expirationDate := time.Now().In(loc).AddDate(DefaultCredentialValidityYears, 0, 0).Format(time.RFC3339)

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

	return NewVerifiableCredential(context, "0", vcType, issuerDocument.ID, time.Now().In(loc).Format(time.RFC3339), expirationDate, "", nil, vcProof, false), nil
}

// VCToJson converts credential to JSON format.
func VCToJson(vc *VerifiableCredential) ([]byte, error) {
	return json.Marshal(vc)
}

// JsonToVC converts JSON to credential object.
func JsonToVC(jsonVC []byte) (*VerifiableCredential, error) {
	vc := &VerifiableCredential{}
	if err := json.Unmarshal(jsonVC, vc); err != nil {
		return nil, err
	}
	return vc, nil
}

// VerifySecp256k1VC verifies a VC with secp256k1 signature.
func VerifySecp256k1VC(vc *VerifiableCredential, expectedBlkID string) (bool, error) {
	copiedVC := *vc
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
	return VerifyJWSSignature(jwsSignature, expectedBlkID, hashedVC[:])
}

// VerifyEIP712VC verifies a VC with EIP712 signature.
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

// VerifyEd25519VC verifies a VC with Ed25519 signature.
func VerifyEd25519VC(vc *VerifiableCredential) (bool, error) {
	copiedVC := *vc
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
	return VerifyEd25519JWSSignature(jwsSignature, pubKey, hashedVC[:])
}

// ConvertVCToBytes converts credential to bytes for hashing.
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
		if err := mapstructure.Decode(vc.CredentialSubject, m); err != nil {
			return nil
		}
		convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(m.ID), []byte(m.Type)}, []byte{})
	case TypeMining:
		m := &MiningLicenseInfo{}
		if err := mapstructure.Decode(vc.CredentialSubject, m); err != nil {
			return nil
		}
		convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(m.ID), []byte(m.Name), []byte(m.Model), []byte(m.Serial)}, []byte{})
	}

	return convertedBytes
}

// ConvertVCToJWTPayload converts VC to JWT payload format.
func ConvertVCToJWTPayload(vc VerifiableCredential) ([]byte, error) {
	var payload JwtCredentialPayload

	payload.Iss = vc.Issuer
	payload.Jti = vc.ID
	expirationTime, err := time.Parse(time.RFC3339, vc.ExpirationDate)
	if err != nil {
		return nil, err
	}
	payload.Exp = expirationTime.Unix()
	issuanceTime, err := time.Parse(time.RFC3339, vc.IssuanceDate)
	if err != nil {
		return nil, err
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
		if err := mapstructure.Decode(vc.CredentialSubject, m); err != nil {
			return nil, err
		}
		payload.Vc.CredentialSubject = m
		payload.Sub = m.ID
	case TypeMining:
		m := &MiningLicenseInfo{}
		if err := mapstructure.Decode(vc.CredentialSubject, m); err != nil {
			return nil, err
		}
		payload.Vc.CredentialSubject = m
		payload.Sub = m.ID
	default:
		return nil, ErrUnknownCredentialType
	}

	return canonicaljson.Marshal(payload)
}

// GenerateEIP712VCTypedDataHash generates the EIP712 typed data hash for a VC.
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
		PrimaryType: EIP712DomainVCPrimaryType,
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
	return common.BytesToHash(crypto.Keccak256(rawData)), nil
}

// ====================
// VP Operations
// ====================

// CreateVPSecp256k1Proof creates a presentation proof using secp256k1 signature.
func CreateVPSecp256k1Proof(vm string, nonce string) Secp256k1VPProof {
	loc, _ := time.LoadLocation("UTC")
	return Secp256k1VPProof{
		BaseProof: BaseProof{
			Type:               Secp256k1Sig,
			VerificationMethod: vm,
			Created:            time.Now().In(loc).Format(time.RFC3339),
			ProofPurpose:       "Authentication",
		},
		JWSSignature: "",
		Nonce:        nonce,
	}
}

// CreateVPEIP712Proof creates a presentation proof using EIP712 signature.
func CreateVPEIP712Proof(vm string, nonce string) EIP712VPProof {
	loc, _ := time.LoadLocation("UTC")
	return EIP712VPProof{
		BaseProof: BaseProof{
			Type:               EIP712Sig,
			VerificationMethod: vm,
			Created:            time.Now().In(loc).Format(time.RFC3339),
			ProofPurpose:       "Authentication",
		},
		ProofValue: "",
		Nonce:      nonce,
	}
}

// CreateVPEd25519Proof creates a presentation proof using Ed25519 signature.
func CreateVPEd25519Proof(vm string, nonce string) Ed25519VPProof {
	loc, _ := time.LoadLocation("UTC")
	return Ed25519VPProof{
		BaseProof: BaseProof{
			Type:               Ed25519Sig,
			VerificationMethod: vm,
			Created:            time.Now().In(loc).Format(time.RFC3339),
			ProofPurpose:       "Authentication",
		},
		JWSSignature:       "",
		PublicKeyMultibase: "",
		Nonce:              nonce,
	}
}

// VerifySecp256k1VP verifies a VP with secp256k1 signature.
func VerifySecp256k1VP(presentation *VerifiablePresentation, expectedBlkID string) (bool, error) {
	copiedVP := *presentation
	proof, ok := copiedVP.Proof.(Secp256k1VPProof)
	if !ok {
		return false, ErrSecp256k1WrongVMType
	}
	jwsSignature := proof.JWSSignature
	proof.JWSSignature = ""
	copiedVP.Proof = proof

	vpBytes, err := ConvertVPToJWTPayload(copiedVP)
	if err != nil {
		return false, err
	}
	hashedVP := crypto.Keccak256(vpBytes)

	return VerifyJWSSignature(jwsSignature, expectedBlkID, hashedVP[:])
}

// VerifyEIP712VP verifies a VP with EIP712 signature.
func VerifyEIP712VP(presentation *VerifiablePresentation, bound *BoundedContract, expectedBlkID string) (bool, error) {
	EIP712DataHash, err := GenerateEIP712VPTypedDataHash(presentation, bound)
	if err != nil {
		return false, err
	}

	EIP712Proof, ok := presentation.Proof.(EIP712VPProof)
	if !ok {
		return false, ErrWrongProofType
	}

	return VerifyEIP712Signature(EIP712Proof.ProofValue, expectedBlkID, EIP712DataHash.Bytes())
}

// VerifyEd25519VP verifies a VP with Ed25519 signature.
func VerifyEd25519VP(presentation *VerifiablePresentation) (bool, error) {
	copiedVP := *presentation
	proof, ok := copiedVP.Proof.(Ed25519VPProof)
	if !ok {
		return false, ErrEd25519WrongVMType
	}
	jwsSignature := proof.JWSSignature
	proof.JWSSignature = ""
	copiedVP.Proof = proof

	_, pubKey, err := multibase.Decode(proof.PublicKeyMultibase)
	if err != nil {
		return false, err
	}

	vpBytes, err := ConvertVPToJWTPayload(copiedVP)
	if err != nil {
		return false, err
	}
	hashedVP := sha512.Sum512(vpBytes)
	return VerifyEd25519JWSSignature(jwsSignature, pubKey, hashedVP[:])
}

// ConvertVPToBytes converts presentation to bytes for hashing.
func ConvertVPToBytes(vp VerifiablePresentation) []byte {
	var convertedBytes []byte

	for _, item := range vp.Context {
		convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(item)}, []byte{})
	}

	for _, item := range vp.Type {
		convertedBytes = bytes.Join([][]byte{convertedBytes, []byte(item)}, []byte{})
	}

	for _, item := range vp.VerifiableCredential {
		convertedBytes = bytes.Join([][]byte{convertedBytes, ConvertVCToBytes(item)}, []byte{})
	}

	return convertedBytes
}

// ConvertVPToJWTPayload converts VP to JWT payload format.
func ConvertVPToJWTPayload(vp VerifiablePresentation) ([]byte, error) {
	var payload JwtPresentationPayload

	payload.Iss = vp.Holder
	switch proof := vp.Proof.(type) {
	case Secp256k1VPProof:
		payload.Nonce = proof.Nonce
		issuanceTime, err := time.Parse(time.RFC3339, proof.Created)
		if err != nil {
			return nil, err
		}
		payload.Iat = issuanceTime.Unix()
	case EIP712VPProof:
		payload.Nonce = proof.Nonce
		issuanceTime, err := time.Parse(time.RFC3339, proof.Created)
		if err != nil {
			return nil, err
		}
		payload.Iat = issuanceTime.Unix()
	case Ed25519VPProof:
		payload.Nonce = proof.Nonce
		issuanceTime, err := time.Parse(time.RFC3339, proof.Created)
		if err != nil {
			return nil, err
		}
		payload.Iat = issuanceTime.Unix()
	default:
		return nil, ErrUnknownProofType
	}

	payload.Vp.Context = vp.Context
	payload.Vp.Type = vp.Type
	payload.Vp.VerifiableCredential = vp.VerifiableCredential

	return canonicaljson.Marshal(payload)
}

// GenerateEIP712VPTypedDataHash generates the EIP712 typed data hash for a VP.
func GenerateEIP712VPTypedDataHash(vp *VerifiablePresentation, bound *BoundedContract) (common.Hash, error) {
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
		"VerifiablePresentation": {
			{Name: "@context", Type: "string[]"},
			{Name: "type", Type: "string[]"},
			{Name: "holder", Type: "string"},
			{Name: "verifiableCredentialData", Type: "bytes"},
		},
	}

	vcBytes, err := canonicaljson.Marshal(vp.VerifiableCredential)
	if err != nil {
		return common.Hash{0}, err
	}

	message := apitypes.TypedDataMessage{
		"@context":                 vp.Context,
		"type":                     vp.Type,
		"holder":                   vp.Holder,
		"verifiableCredentialData": crypto.Keccak256(vcBytes),
	}

	typedData := apitypes.TypedData{
		Types:       types,
		PrimaryType: EIP712DomainVPPrimaryType,
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
	return common.BytesToHash(crypto.Keccak256(rawData)), nil
}
