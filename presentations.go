package did

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"github.com/gibson042/canonicaljson-go"
)

func CreateVPSecp256k1Proof(vm string, nonce string) Secp256k1VPProof {
	loc, _ := time.LoadLocation("UTC")
	presentationProof := CreateSecp256k1VPProof()
	presentationProof.Type = Secp256k1Sig
	presentationProof.VerificationMethod = vm
	presentationProof.JWSSignature = ""
	presentationProof.Created = time.Now().In(loc).Format(time.RFC3339)
	presentationProof.ProofPurpose = "Authentication"
	presentationProof.Nonce = nonce
	return *presentationProof
}

func CreateVPEIP712Proof(vm string, nonce string) EIP712VPProof {
	loc, _ := time.LoadLocation("UTC")
	presentationProof := CreateEIP712VPProof()
	presentationProof.Type = EIP712Sig
	presentationProof.VerificationMethod = vm
	presentationProof.ProofValue = ""
	presentationProof.Created = time.Now().In(loc).Format(time.RFC3339)
	presentationProof.ProofPurpose = "Authentication"
	presentationProof.Nonce = nonce
	return *presentationProof
}

// create a presentation using 1 or more credentials. Currently unused
func CreatePresentation(credentials []VerifiableCredential, holderDocument DIDDocument, holderPrivKey *ecdsa.PrivateKey, nonce string, proofType string, bound *BoundedContract) (*VerifiablePresentation, error) {
	var presentation *VerifiablePresentation
	var presentationProof interface{}
	var context []string
	presentationType := []string{"VerifiablePresentation"}
	switch proofType {
	case Secp256k1Sig:
		presentationProof = CreateVPSecp256k1Proof(holderDocument.Authentication, nonce)
		context = []string{ContextSecp256k1, ContextCredential}
		presentation = NewPresentation(context, presentationType, credentials, holderDocument.ID, presentationProof)
	case EIP712Sig:
		presentationProof = CreateVPEIP712Proof(holderDocument.Authentication, nonce)
		context = []string{ContextEIP712, ContextCredential}
		presentation = NewPresentation(context, presentationType, credentials, holderDocument.ID, presentationProof)
	default:
		return nil, ErrUnknownProofType
	}

	//Create the proof's signature using a stringified version of the VP and the holder's private key.
	//This way, the signature can be verified by re-stringifying the VP and looking up the public key in the holder's DID document.
	//Verification will only succeed if the VP was unchanged since the signature and if the holder
	//public key matches the private key used to make the signature

	//This proof is only for the presentation itself; each credential also needs to be individually verified
	switch proof := presentation.Proof.(type) {
	case Secp256k1VPProof:
		vpBytes, err := ConvertVPToJWTPayload(*presentation)
		if err != nil {
			return presentation, err
		}
		hashedVP := sha256.Sum256(vpBytes)
		signatureData, err := CreateJWSSignature(holderPrivKey, hashedVP[:])
		if err != nil {
			return nil, err
		}
		proof.JWSSignature = signatureData
		presentation.Proof = proof
	case EIP712VPProof:
		typedHash, err := GenerateEIP712VPTypedDataHash(presentation, *bound)
		if err != nil {
			return nil, err
		}
		signatureData, err := CreateEIP712Signature(holderPrivKey, typedHash)
		if err != nil {
			return nil, err
		}
		proof.ProofValue = signatureData
		presentation.Proof = proof
	default:
		return nil, ErrUnknownProofType
	}

	return presentation, nil
}

// Verify a presentation. Need to first verify the presentation's proof using the holder's DID document.
// Afterwards, need to verify the proof of each credential included inside the presentation
func VerifyVP(presentation *VerifiablePresentation, bound *BoundedContract) (bool, error) {

	resolutionMeta, holderDoc, _ := Resolve(presentation.Holder, CreateResolutionOptions(), bound)
	if resolutionMeta.Error != "" {
		return false, errors.New(resolutionMeta.Error)
	}

	var success bool
	var err error
	switch proof := presentation.Proof.(type) {
	case Secp256k1VPProof:
		//get verification method from the issuer DID document which is listed in the vc proof
		targetVM, err := holderDoc.RetrieveVerificationMethod(proof.VerificationMethod)
		if err != nil {
			return false, err
		}
		if targetVM.MethodType != Secp256k1Key { //vm must be the same type as the proof
			return false, ErrSecp256k1WrongVMType
		}
		success, err = VerifySecp256k1VP(presentation, targetVM.BlockchainAccountId)
		if err != nil {
			return false, err
		}
	case EIP712VPProof:
		//get verification method from the issuer DID document which is listed in the vc proof
		targetVM, err := holderDoc.RetrieveVerificationMethod(proof.VerificationMethod)
		if err != nil {
			return false, err
		}
		if targetVM.MethodType != Secp256k1Key { //vm must be the same type as the proof
			return false, ErrSecp256k1WrongVMType
		}
		success, err = VerifyEIP712VP(presentation, bound, targetVM.BlockchainAccountId)
		if err != nil {
			return false, err
		}
	default:
		return false, ErrUnknownProofType
	}
	if !success {
		return false, err
	}

	for _, credential := range presentation.VerifiableCredential { //verify each individual credential stored in the presentation
		success, err = VerifyVC(&credential, bound)
		if !success {
			return false, err
		}
	}

	return true, nil
}

// Verify that the provided public key matches the signature in the proof.
// Since we've made sure that the address in the holder vm matches this public key,
// verifying the signature here proves that the signature was made with the holder's private key
func VerifySecp256k1VP(presentation *VerifiablePresentation, expectedBlkID string) (bool, error) {
	copiedVP := *presentation
	//have to make sure to remove the signature from the copy, as the original did not have a signature at the time the signature was generated
	proof, ok := copiedVP.Proof.(Secp256k1VCProof)
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
	hashedVP := sha256.Sum256(vpBytes)

	result, err := VerifyJWSSignature(jwsSignature, expectedBlkID, hashedVP[:])
	if err != nil {
		return false, err
	}
	return result, nil
}

func VerifyEIP712VP(presentation *VerifiablePresentation, bound *BoundedContract, expectedBlkID string) (bool, error) {

	EIP712DataHash, err := GenerateEIP712VPTypedDataHash(presentation, *bound)
	if err != nil {
		return false, err
	}

	EIP712Proof, ok := presentation.Proof.(EIP712VPProof)
	if !ok {
		return false, ErrWrongProofType
	}

	return VerifyEIP712Signature(EIP712Proof.ProofValue, expectedBlkID, EIP712DataHash.Bytes())
}

// convert presentation to bytes so it can be hashed
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

func ConvertVPToJWTPayload(vp VerifiablePresentation) (payloadByte []byte, err error) {

	var payload JwtPresentationPayload
	payloadByte = []byte{}

	payload.Iss = vp.Holder // holder is the issuer of the JWT presentation
	switch proof := vp.Proof.(type) {
	case Secp256k1VPProof:
		payload.Nonce = proof.Nonce
		issuanceTime, err := time.Parse(time.RFC3339, proof.Created) // We use the Proof Created time as the JWT Issued At time
		if err != nil {
			return payloadByte, err
		}
		payload.Iat = issuanceTime.Unix()
	case EIP712VPProof:
		payload.Nonce = proof.Nonce
		issuanceTime, err := time.Parse(time.RFC3339, proof.Created) // We use the Proof Created time as the JWT Issued At time
		if err != nil {
			return payloadByte, err
		}
		payload.Iat = issuanceTime.Unix()

	default:
		return payloadByte, ErrUnknownProofType
	}

	payload.Vp.Context = vp.Context
	payload.Vp.Type = vp.Type
	payload.Vp.VerifiableCredential = vp.VerifiableCredential

	payloadByte, err = canonicaljson.Marshal(payload)
	if err != nil {
		return payloadByte, err
	}

	return payloadByte, nil
}

func GenerateEIP712VPTypedDataHash(vp *VerifiablePresentation, bound BoundedContract) (common.Hash, error) {

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
		PrimaryType: EIP712DomainVPPrimayType,
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
