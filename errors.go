package did

import "errors"

var (
	ErrRenewRevoked          = errors.New("VC has been revoked, cannot renew")
	ErrUnknownIssuer         = errors.New("unknown issuer")
	ErrSecp256k1WrongVMType  = errors.New("must use a verification method with a type of 'EcdsaSecp256k1RecoveryMethod2020' to verify a 'EcdsaSecp256k1Signature2019' proof")
	ErrEd25519WrongVMType    = errors.New("must use a verification method with a type of 'Ed25519VerificationKey2020' to verify a 'Ed25519Signature2020' proof")
	ErrUnknownProofType      = errors.New("unknown proof type")
	ErrUnknownCredentialType = errors.New("unknown credential type")
	ErrWrongProofType        = errors.New("proof type is incorrect")
	ErrMissingVM             = errors.New("failed to find verification method")
	ErrWrongAddress          = errors.New("provided public key does not match issuer address")
	ErrETHAddress            = errors.New("provided address is not a correct ETH address")
	ErrInvalidDID            = errors.New("provided DID is invalid")
	ErrInValidSignature      = errors.New("provided signature is invalid")
	ErrInvalidBlockID        = errors.New("provided Block Account ID is invalid")
	ErrUnknownChainID        = errors.New("provided Chain ID is invalid")
	ErrUnknownChainName      = errors.New("provided Chain Name is invalid")
	ErrUnsupportedKeyType    = errors.New("provided key type is not supported on this chain")
	ErrInsufficientBalance   = errors.New("insufficient balance for transaction")

	// DID validation errors
	ErrDIDWrongSectionCount = errors.New("DID must have exactly 3 or 4 sections")
	ErrDIDInvalidPrefix     = errors.New("DID must start with 'did'")
	ErrDIDInvalidMethodName = errors.New("DID method name must be 'metablox'")
	ErrDIDInvalidIdentifier = errors.New("DID identifier section is formatted incorrectly")
	ErrDIDEmptyIdentifier   = errors.New("DID identifier is empty")
)
