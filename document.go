package did

import "crypto/ecdsa"

type DOCExtra struct {
	VerificationMethod   []VMethod `json:"verificationMethod,omitempty"`
	AssertionMethod      []string  `json:"assertionMethod,omitempty"`
	KeyAgreement         []string  `json:"keyAgreement,omitempty"`
	CapabilityInvocation []string  `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation []string  `json:"capabilityDelegation,omitempty"`
	Service              []Service `json:"service,omitempty"`
}

type Metadata struct {
	Created     string
	Updated     string
	Deactivated bool
	VersionId   string
}

type VMethod struct {
	Id         string `json:"id"`
	kind       string `json:"type"`
	controller string `json:"controller"`
}

type Service struct {
	Id              string `json:"id"`
	kind            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

type DID interface {
	Create() (*ecdsa.PrivateKey, error)
	Resolve(document string) (*Document, error)
}

// Document The DID document
type Document struct {
	metadata             Metadata
	controller           []string
	docExtra             DOCExtra
	Context              []string  `json:"@context"`
	Id                   string    `json:"id"`
	Kind                 string    `json:"type"`
	Controller           []string  `json:"controller"`
	Created              string    `json:"created"`
	Updated              string    `json:"updated"`
	VersionId            string    `json:"versionId"`
	Deactivated          bool      `json:"deactivated"`
	VerificationMethod   []VMethod `json:"verificationMethod,omitempty"`
	AssertionMethod      []string  `json:"assertionMethod,omitempty"`
	KeyAgreement         []string  `json:"keyAgreement,omitempty"`
	CapabilityInvocation []string  `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation []string  `json:"capabilityDelegation,omitempty"`
	Service              []Service `json:"service"`
}

//func (b Document) MarshalJSON() ([]byte, error) {
//
//	return nil, nil
//}
//
//func (b Document) UnmarshalJSON(bytes []byte) error {
//
//	return nil
//}
