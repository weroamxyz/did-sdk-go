package did

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/weroamxyz/did-sdk-go/v2/registry"
)

type ContractConfig struct {
	RpcUrl       string
	ContractAddr string
	ChainName    string
}

type BoundedContract struct {
	ContractAddr common.Address
	Client       *ethclient.Client
	Instance     *registry.Registry
	ChainID      *big.Int
	ChainName    string
}

type DIDDocument struct {
	Context            []string             `json:"@context" mapstructure:"@context"`
	ID                 string               `json:"id"`
	Created            string               `json:"created"`
	Updated            string               `json:"updated"`
	Version            int                  `json:"version"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     string               `json:"authentication"`
	AssertionMethod    string               `json:"assertionMethod"`
	Service            []Service            `json:"service"`
}
type VerificationMethod struct {
	ID                  string `json:"id"`
	MethodType          string `json:"type"`
	Controller          string `json:"controller"`
	BlockchainAccountId string `json:"blockchainAccountId"`
}

type ResolutionOptions struct {
	Accept string `json:"accept"`
}

type RepresentationResolutionOptions struct {
	Accept string `json:"accept"`
}

type ResolutionMetadata struct {
	Error string `json:"error"`
}

type RepresentationResolutionMetadata struct {
	ContentType string `json:"contentType"`
	Error       string `json:"error"`
}

type DocumentMetadata struct {
	Created       string   `json:"created"`
	Updated       string   `json:"updated"`
	Deactivated   string   `json:"deactivated"`
	NextUpdate    string   `json:"nextUpdate"`
	VersionID     string   `json:"versionId"`
	NextVersionID string   `json:"nextVersionId"`
	EquivalentID  []string `json:"equivalentId"`
	CanonicalID   string   `json:"canonicalId"`
}

type VerifiableCredential struct {
	Context           []string    `json:"@context" mapstructure:"@context"`
	ID                string      `json:"id" db:"ID"`
	Type              []string    `json:"type"`
	Issuer            string      `json:"issuer" db:"Issuer"`
	IssuanceDate      string      `json:"issuanceDate" db:"IssuanceDate"`
	ExpirationDate    string      `json:"expirationDate" db:"ExpirationDate"`
	Description       string      `json:"description" db:"Description"`
	CredentialSubject interface{} `json:"credentialSubject"`
	Proof             interface{} `json:"proof"`
	Revoked           bool        `json:"revoked" db:"Revoked"`
}

type JwtCredentialPayload struct {
	Exp int64  `json:"exp,omitempty"` // Expiration
	Iat int64  `json:"iat,omitempty"` // Issued At
	Iss string `json:"iss,omitempty"` // Issuer
	Jti string `json:"jti,omitempty"` // JWT ID
	Nbf int64  `json:"nbf,omitempty"` // Not Valid Before
	Sub string `json:"sub,omitempty"` // Subject
	Vc  struct {
		Context           []string    `json:"@context" mapstructure:"@context"`
		CredentialSubject interface{} `json:"credentialSubject"`
		Type              []string    `json:"type"`
		Description       string      `json:"description"`
		Revoked           bool        `json:"revoked"`
	} `json:"vc,omitempty"` // Verifiable Credential
}

// This can be a type of input form to set up the VC.
// Temp fields here currently, will be changed in the future
type SubjectInfo struct {
	ID           string `json:"id"`
	GivenName    string `json:"givenName"`
	FamilyName   string `json:"familyName"`
	Gender       string `json:"gender"`
	BirthCountry string `json:"birthCountry"`
	BirthDate    string `json:"birthName"`
}

// BaseProof contains the common fields shared by all proof types.
type BaseProof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
}

type Secp256k1VCProof struct {
	BaseProof
	JWSSignature string `json:"jws"` // signature is created from a hash of the VC
}

type EIP712VCProof struct {
	BaseProof
	ProofValue string `json:"proofValue"`
}

type Ed25519VCProof struct {
	BaseProof
	PublicKeyMultibase string `json:"publicKeyMultibase"`
	JWSSignature       string `json:"jws"` // signature is created from a hash of the VC
}

type EIP712VC struct {
	Domain      EIP712Domain `json:"domain"`
	Types       string       `json:"types"`
	PrimaryType string       `json:"primaryType"`
}

type VerifiablePresentation struct {
	Context              []string               `json:"@context" mapstructure:"@context"`
	Type                 []string               `json:"type"`
	VerifiableCredential []VerifiableCredential `json:"verifiableCredential"`
	Holder               string                 `json:"holder"`
	Proof                interface{}            `json:"proof"`
}

type JwtPresentationPayload struct {
	Exp   int64  `json:"exp,omitempty"`   // Expiration
	Iat   int64  `json:"iat,omitempty"`   // Issued At
	Iss   string `json:"iss,omitempty"`   // Issuer, the holder of VP
	Nbf   int64  `json:"nbf,omitempty"`   // Not Valid Before
	Nonce string `json:"nonce,omitempty"` // Random value generated by verifier that must be included in proof
	Vp    struct {
		Context              []string               `json:"@context" mapstructure:"@context"`
		Type                 []string               `json:"type"`
		VerifiableCredential []VerifiableCredential `json:"verifiableCredential"`
	} `json:"vp"`
}

type Secp256k1VPProof struct {
	BaseProof
	JWSSignature string `json:"jws"`   // signature is created from a hash of the VP
	Nonce        string `json:"nonce"` // random value generated by verifier that must be included in proof
}

type EIP712VPProof struct {
	BaseProof
	ProofValue string `json:"proofValue"`
	Nonce      string `json:"nonce"` // random value generated by verifier that must be included in proof
}

type Ed25519VPProof struct {
	BaseProof
	PublicKeyMultibase string `json:"publicKeyMultibase"`
	JWSSignature       string `json:"jws"`   // signature is created from a hash of the VP
	Nonce              string `json:"nonce"` // random value generated by verifier that must be included in proof
}

type EIP712VP struct {
	Domain      EIP712Domain `json:"domain"`
	Types       string       `json:"types"`
	PrimaryType string       `json:"primaryType"`
}

type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

type WifiAccessInfo struct {
	CredentialID string `json:"-" db:"CredentialID"`
	ID           string `json:"id" db:"ID"`     //id of the user the credential is assigned to
	Type         string `json:"type" db:"Type"` //user or validator
}

type MiningLicenseInfo struct {
	CredentialID string `json:"-" db:"CredentialID"`
	ID           string `json:"id" db:"ID"`     //id of the user the credential is assigned to
	Name         string `json:"name" db:"Name"` //manufacturer name
	Model        string `json:"model" db:"Model"`
	Serial       string `json:"serial" db:"Serial"` //serial number
}

type VCSchemaChanged struct {
	VcName string
	Name   [32]byte
	Value  []byte
}

type EIP712VCData struct {
	Types       interface{}  `json:"types"`
	Domain      EIP712Domain `json:"domain"`
	PrimaryType string       `json:"primaryType"`
	Message     EIP712VC     `json:"message"`
}

type EIP712VPData struct {
	Types       interface{}  `json:"types"`
	Domain      EIP712Domain `json:"domain"`
	PrimaryType string       `json:"primaryType"`
	Message     EIP712VP     `json:"message"`
}

type EIP712Domain struct {
	Name              string `json:"name"`
	ChainID           string `json:"chainID"`
	VerifyingContract string `json:"verifyingContract"`
	Version           string `json:"version"`
}

func (doc DIDDocument) RetrieveVerificationMethod(vmID string) (VerificationMethod, error) {
	for _, vm := range doc.VerificationMethod {
		if vm.ID == vmID {
			return vm, nil
		}
	}
	return VerificationMethod{}, ErrMissingVM
}

func (doc *DIDDocument) AddService(service Service) {
	doc.Service = append(doc.Service, service)
}

func NewVerifiableCredential(context []string, id string, vctype []string, issuer, issuanceDate, expirationDate, description string, subject interface{}, proof interface{}, revoked bool) *VerifiableCredential {
	return &VerifiableCredential{
		Context:           context,
		ID:                id,
		Type:              vctype,
		Issuer:            issuer,
		IssuanceDate:      issuanceDate,
		ExpirationDate:    expirationDate,
		Description:       description,
		CredentialSubject: subject,
		Proof:             proof,
		Revoked:           revoked,
	}
}

func NewPresentation(context, presentationType []string, credentials []VerifiableCredential, holder string, proof interface{}) *VerifiablePresentation {
	return &VerifiablePresentation{
		Context:              context,
		Type:                 presentationType,
		VerifiableCredential: credentials,
		Holder:               holder,
		Proof:                proof,
	}
}

func NewSubjectInfo(id string, givenName, familyName, gender, birthCountry, birthDate string) *SubjectInfo {
	return &SubjectInfo{
		ID:           id,
		GivenName:    givenName,
		FamilyName:   familyName,
		Gender:       gender,
		BirthCountry: birthCountry,
		BirthDate:    birthDate,
	}
}

func NewWifiAccessInfo(credentialID, id, userType string) *WifiAccessInfo {
	return &WifiAccessInfo{
		CredentialID: credentialID,
		ID:           id,
		Type:         userType,
	}
}

func NewMiningLicenseInfo(credentialID, id, name, model, serial string) *MiningLicenseInfo {
	return &MiningLicenseInfo{
		CredentialID: credentialID,
		ID:           id,
		Name:         name,
		Model:        model,
		Serial:       serial,
	}
}

func NewVCProof(proofType, created, vm, purpose, sig string) *Secp256k1VCProof {
	return &Secp256k1VCProof{
		BaseProof: BaseProof{
			Type:               proofType,
			Created:            created,
			VerificationMethod: vm,
			ProofPurpose:       purpose,
		},
		JWSSignature: sig,
	}
}

func NewVPProof(proofType, created, vm, purpose, sig, nonce string) *Secp256k1VPProof {
	return &Secp256k1VPProof{
		BaseProof: BaseProof{
			Type:               proofType,
			Created:            created,
			VerificationMethod: vm,
			ProofPurpose:       purpose,
		},
		JWSSignature: sig,
		Nonce:        nonce,
	}
}

