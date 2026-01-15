// Package did provides DID (Decentralized Identifier) operations for MetaBlox according to W3C spec.
package did

// Signature and key type constants
const (
	Secp256k1Sig = "EcdsaSecp256k1Signature2019"
	Secp256k1Key = "EcdsaSecp256k1RecoveryMethod2020"
	EIP712Sig    = "Eip712Signature2021"
	Ed25519Sig   = "Ed25519Signature2020"
	Ed25519Key   = "Ed25519VerificationKey2020"
	PurposeAuth  = "Authentication"
)

// Context URIs
const (
	ContextDID        = "https://w3id.org/did/v1"
	ContextCredential = "https://www.w3.org/2018/credentials/v1"
	ContextSecp256k1  = "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#"
	ContextEd25519    = "https://w3id.org/security/suites/ed25519-2020/v1"
	ContextEIP712     = "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec"
)

// Credential and presentation types
const (
	TypeCredential   = "VerifiableCredential"
	TypePresentation = "VerifiablePresentation"
	TypeWifi         = "WifiAccess"
	TypeMining       = "MiningLicense"
)

// EIP712 domain constants
const (
	EIP712DomainVersion       = "1"
	EIP712DomainName          = "EIP712Verifiable"
	EIP712DomainVCPrimaryType = "VerifiableCredential"
	EIP712DomainVPPrimaryType = "VerifiablePresentation"
)

// Transaction configuration constants
const (
	DefaultGasLimit      = uint64(300000)
	DefaultGasLimitInt64 = int64(300000)
)

// Credential validity constants
const (
	DefaultCredentialValidityYears = 10
)

// Credential ID base string
const BaseIDString = "https://metablox.io/credentials/"
