package did

import "errors"

var (
	ErrRenewRevoked         = errors.New("VC has been revoked, cannot renew")
	ErrUnknownIssuer        = errors.New("unknown issuer")
	ErrSecp256k1WrongVMType = errors.New("must use a verification method with a type of 'EcdsaSecp256k1RecoveryMethod2020' to verify a 'EcdsaSecp256k1Signature2019' proof")
	ErrUnknownProofType     = errors.New("unable to verify unknown proof type")
	ErrMissingVM            = errors.New("failed to find verification method")
	ErrWrongAddress         = errors.New("provided public key does not match issuer address")
)
