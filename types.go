package did

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/MetaBloxIO/did-sdk-go/v2/registry"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
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

type Secp256k1VCProof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	JWSSignature       string `json:"jws"` //signature is created from a hash of the VC
}

type EIP712VCProof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	//EIP712             EIP712VC `json:"eip712"`
	ProofValue string `json:"proofValue"`
}

type Ed25519VCProof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
	JWSSignature       string `json:"jws"` //signature is created from a hash of the VC
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
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	JWSSignature       string `json:"jws"`   //signature is created from a hash of the VP
	Nonce              string `json:"nonce"` //random value generated by verifier that must be included in proof
}

type EIP712VPProof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	//EIP712             EIP712VP `json:"eip712"`
	ProofValue string `json:"proofValue"`
	Nonce      string `json:"nonce"` //random value generated by verifier that must be included in proof
}

type Ed25519VPProof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
	JWSSignature       string `json:"jws"`   //signature is created from a hash of the VP
	Nonce              string `json:"nonce"` //random value generated by verifier that must be included in proof
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
	Doamin      EIP712Domain `json:"domain"`
	PrimaryType string       `json:"primaryType"`
	Message     EIP712VC     `json:"message"`
}

type EIP712VPData struct {
	Types       interface{}  `json:"types"`
	Doamin      EIP712Domain `json:"domain"`
	PrimaryType string       `json:"primaryType"`
	Message     EIP712VP     `json:"message"`
}

type EIP712Domain struct {
	Name              string `json:"name"`
	ChainID           string `json:"chainID"`
	VerifyingContract string `json:"verifyingContract"`
	Version           string `json:"version"`
}

func CreateDIDDocument() *DIDDocument {
	return &DIDDocument{}
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

func CreateVerifiableCredential() *VerifiableCredential {
	return &VerifiableCredential{}
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

func CreateSubjectInfo() *SubjectInfo {
	return &SubjectInfo{}
}

func CreateWifiAccessInfo() *WifiAccessInfo {
	return &WifiAccessInfo{}
}

func CreateMiningLicenseInfo() *MiningLicenseInfo {
	return &MiningLicenseInfo{}
}

func CreateSecp256k1VCProof() *Secp256k1VCProof {
	return &Secp256k1VCProof{}
}

func CreateSecp256k1VPProof() *Secp256k1VPProof {
	return &Secp256k1VPProof{}
}

func CreateEIP712VCProof() *EIP712VCProof {
	return &EIP712VCProof{}
}

func CreateEIP712VPProof() *EIP712VPProof {
	return &EIP712VPProof{}
}

func CreateEd25519VCProof() *Ed25519VCProof {
	return &Ed25519VCProof{}
}

func CreateEd25519VPProof() *Ed25519VPProof {
	return &Ed25519VPProof{}
}

func CreateResolutionOptions() *ResolutionOptions {
	return &ResolutionOptions{}
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

func GenerateTestPrivKey() *ecdsa.PrivateKey {
	privKey, _ := crypto.ToECDSA(common.Hex2Bytes("dbbd9634560466ac9713e0cf10a575456c8b55388bce0c044f33fc6074dc5ae6"))
	return privKey
}

func GenerateTestDIDDocument() *DIDDocument {
	document := CreateDIDDocument()
	document.Context = append(document.Context, ContextSecp256k1)
	document.Context = append(document.Context, ContextDID)
	document.ID = "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX"
	document.Created = "2022-03-31T12:53:19-07:00"
	document.Updated = "2022-03-31T12:53:19-07:00"
	document.Version = 1
	document.VerificationMethod = append(document.VerificationMethod, VerificationMethod{ID: "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification", MethodType: "EcdsaSecp256k1RecoveryMethod2020", Controller: "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX", BlockchainAccountId: "eip155:1666600000:0xBE1e1dB948CC1f441514aFb8924B67891f1c6889"})
	document.Authentication = "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification"
	return document
}

func GenerateTestResolvedDIDDocument() *DIDDocument {
	document := GenerateTestDIDDocument()
	document.VerificationMethod[0].BlockchainAccountId = "eip155:1666600000:0x25007b7AB5b0717F2Edd155F70746719e1862A52"
	return document
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

func NewWifiAccessInfo(credentialID, id, userType string) *WifiAccessInfo {
	return &WifiAccessInfo{
		CredentialID: credentialID,
		ID:           id,
		Type:         userType,
	}
}

func GenerateTestWifiAccessInfo() *WifiAccessInfo {
	return NewWifiAccessInfo(
		"sampleID",
		"did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
		"User",
	)
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

func GenerateTestMiningLicenseInfo() *MiningLicenseInfo {
	return NewMiningLicenseInfo(
		"1",
		"did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
		"TestName",
		"TestModel",
		"TestSerial",
	)
}

func NewVCProof(proofType, created, vm, purpose, sig string) *Secp256k1VCProof {
	return &Secp256k1VCProof{
		Type:               proofType,
		Created:            created,
		VerificationMethod: vm,
		ProofPurpose:       purpose,
		JWSSignature:       sig,
	}
}

func NewVPProof(proofType, created, vm, purpose, sig, nonce string) *Secp256k1VPProof {
	return &Secp256k1VPProof{
		Type:               proofType,
		Created:            created,
		VerificationMethod: vm,
		ProofPurpose:       purpose,
		JWSSignature:       sig,
		Nonce:              nonce,
	}
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

func CreateService() *Service {
	return &Service{}
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
