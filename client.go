package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
)

// Chain name constants
const (
	EthereumChainName string = "ethereum" // Used for DID parsing default
	SolanaChainName   string = "solana"
	HarmonyChainName  string = "harmony"
)

// Default RPC URLs (can be overridden via environment variables)
const (
	DefaultHarmonyRPCURL = "https://api.harmony.one"
	DefaultSolanaRPCURL  = "https://245022926.rpc.thirdweb.com"
)

// Contract addresses
const (
	HarmonyContractAddr = "0x275D3fC4C492a8d743Fe9AAB42266fEf92c89995"
	SolanaContractAddr  = "0x58C2AE9AE47a07A3D9928898BA32C00E4FE599Cc"
)

// getContractConfig returns the contract configuration for a given chain name.
// rpcOverride allows explicit RPC URL configuration; falls back to env var then default.
func getContractConfig(chainName string, rpcOverride string) (ContractConfig, bool) {
	getRPC := func(override, envKey, defaultVal string) string {
		if override != "" {
			return override
		}
		if rpc := os.Getenv(envKey); rpc != "" {
			return rpc
		}
		return defaultVal
	}

	switch chainName {
	case HarmonyChainName:
		rpc := getRPC(rpcOverride, "DID_HARMONY_RPC_URL", DefaultHarmonyRPCURL)
		return ContractConfig{RpcUrl: rpc, ContractAddr: HarmonyContractAddr, ChainName: HarmonyChainName}, true
	case SolanaChainName:
		rpc := getRPC(rpcOverride, "DID_SOLANA_RPC_URL", DefaultSolanaRPCURL)
		return ContractConfig{RpcUrl: rpc, ContractAddr: SolanaContractAddr, ChainName: SolanaChainName}, true
	default:
		return ContractConfig{}, false
	}
}

var ChainId2NameMap = map[int]string{
	1:          EthereumChainName,
	1666600000: HarmonyChainName,
	245022926:  SolanaChainName,
}

var ChainName2IdMap = map[string]int{
	EthereumChainName: 1,
	HarmonyChainName:  1666600000,
	SolanaChainName:   245022926,
}

// Client encapsulates the DID SDK state and provides methods for DID operations.
// This is the recommended way to use the SDK as it avoids global state.
type Client struct {
	issuerDIDs       []string
	ecPrivateKey     *ecdsa.PrivateKey
	edPrivateKey     *ed25519.PrivateKey
	chainID          *big.Int
	boundedContracts map[string]*BoundedContract
}

// ClientConfig holds the configuration for creating a new Client.
type ClientConfig struct {
	Passphrase string            `json:"passphrase"`
	Keystore   string            `json:"keystore"`
	Chains     map[string]string `json:"chains"` // chain name -> RPC URL (empty string uses default)
}

// NewClient creates a new Client instance with the provided configuration.
func NewClient(cfg *ClientConfig) (*Client, error) {
	client := &Client{
		boundedContracts: make(map[string]*BoundedContract),
	}

	ecPrivKey, err := keystoreToPrivateKey(cfg.Keystore, cfg.Passphrase)
	if err != nil {
		return nil, err
	}
	client.ecPrivateKey = ecPrivKey

	// Generate ED25519 key from EC key signature
	var edkeySeed [ed25519.SeedSize]byte
	sig, err := crypto.Sign(crypto.Keccak256([]byte("MetaBloxED25519")), ecPrivKey)
	if err != nil {
		return nil, err
	}
	edkeySeed = sha256.Sum256(sig)
	deterministicKey := ed25519.NewKeyFromSeed(edkeySeed[:])
	client.edPrivateKey = &deterministicKey

	// Initialize issuer DIDs and bounded contracts
	if err := client.initChains(cfg.Chains); err != nil {
		return nil, err
	}

	return client, nil
}

func keystoreToPrivateKey(privateKeyFile, password string) (*ecdsa.PrivateKey, error) {
	keystoreJSON, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}
	key, err := keystore.DecryptKey(keystoreJSON, password)
	if err != nil {
		return nil, err
	}
	return key.PrivateKey, nil
}

func (c *Client) initChains(chains map[string]string) error {
	c.issuerDIDs = make([]string, 0)

	for chainName, rpcURL := range chains {
		_, ok := ChainName2IdMap[chainName]
		if !ok {
			return ErrUnknownChainName
		}

		// Initialize issuer DID
		if chainName == SolanaChainName {
			solPubKey, _ := c.edPrivateKey.Public().(ed25519.PublicKey)
			c.issuerDIDs = append(c.issuerDIDs, GenerateDIDString(&solPubKey, chainName))
		} else if chainName == EthereumChainName {
			c.issuerDIDs = append(c.issuerDIDs, GenerateDIDString(&c.ecPrivateKey.PublicKey, chainName))
			c.issuerDIDs = append(c.issuerDIDs, GenerateDIDString(&c.ecPrivateKey.PublicKey, ""))
		} else {
			c.issuerDIDs = append(c.issuerDIDs, GenerateDIDString(&c.ecPrivateKey.PublicKey, chainName))
		}

		// Initialize bounded contract
		contractConfig, ok := getContractConfig(chainName, rpcURL)
		if !ok {
			continue // Chain doesn't have contract config (e.g., ethereum)
		}

		boundedContract, err := GetRegistryInstance(contractConfig)
		if err != nil {
			return err
		}
		c.boundedContracts[chainName] = boundedContract
	}
	return nil
}

// GetIssuerDIDs returns all issuer DIDs.
func (c *Client) GetIssuerDIDs() []string {
	return c.issuerDIDs
}

// GetIssuerDIDFromChainName returns the issuer DID for a specific chain name.
func (c *Client) GetIssuerDIDFromChainName(targetChainName string) (string, error) {
	for _, did := range c.issuerDIDs {
		didChainName, err := GetChainNameFromDID(did)
		if err != nil {
			continue
		}
		if didChainName == targetChainName {
			return did, nil
		}
	}
	return "", ErrUnknownChainName
}

// GetIssuerDIDFromChainID returns the issuer DID for a specific chain ID.
func (c *Client) GetIssuerDIDFromChainID(targetChainID int) (string, error) {
	targetChainName, ok := ChainId2NameMap[targetChainID]
	if !ok {
		return "", ErrUnknownChainID
	}
	return c.GetIssuerDIDFromChainName(targetChainName)
}

// GetECPrivateKey returns the ECDSA private key.
func (c *Client) GetECPrivateKey() *ecdsa.PrivateKey {
	return c.ecPrivateKey
}

// GetEDPrivateKey returns the Ed25519 private key.
func (c *Client) GetEDPrivateKey() *ed25519.PrivateKey {
	return c.edPrivateKey
}

// GetChainID returns the chain ID.
func (c *Client) GetChainID() *big.Int {
	return c.chainID
}

// GetBoundedContract returns the bounded contract for a specific chain name.
func (c *Client) GetBoundedContract(chainName string) (*BoundedContract, error) {
	boundedContract, ok := c.boundedContracts[chainName]
	if !ok {
		return nil, ErrUnknownChainName
	}
	return boundedContract, nil
}

// CheckIssuer checks if the provided DID is one of the issuer DIDs.
func (c *Client) CheckIssuer(did string) bool {
	_, _, isEth := parseAddress(did)
	for _, issuerDid := range c.issuerDIDs {
		if isEth {
			if strings.EqualFold(issuerDid, did) {
				return true
			}
		} else if issuerDid == did {
			return true
		}
	}
	return false
}

// AddIssuer adds a new issuer DID.
func (c *Client) AddIssuer(did string) error {
	_, valid := PrepareDID(did)
	if !valid {
		return ErrInvalidDID
	}
	c.issuerDIDs = append(c.issuerDIDs, did)
	return nil
}

// RemoveIssuer removes an issuer DID.
func (c *Client) RemoveIssuer(did string) error {
	for i, issuerDid := range c.issuerDIDs {
		if issuerDid == did {
			c.issuerDIDs = append(c.issuerDIDs[:i], c.issuerDIDs[i+1:]...)
			return nil
		}
	}
	return ErrUnknownIssuer
}

// VerifyVC verifies a verifiable credential.
func (c *Client) VerifyVC(vc *VerifiableCredential) (bool, error) {
	if err := ParseVCProof(vc); err != nil {
		return false, err
	}

	if !c.CheckIssuer(vc.Issuer) {
		return false, ErrUnknownIssuer
	}

	issuerChainName, err := GetChainNameFromDID(vc.Issuer)
	if err != nil {
		return false, err
	}
	bound, err := c.GetBoundedContract(issuerChainName)
	if err != nil {
		return false, err
	}

	resolutionMeta, issuerDoc, _ := Resolve(vc.Issuer, &ResolutionOptions{}, bound)
	if resolutionMeta.Error != "" {
		return false, errors.New(resolutionMeta.Error)
	}

	switch proof := vc.Proof.(type) {
	case Secp256k1VCProof:
		targetVM, err := issuerDoc.RetrieveVerificationMethod(proof.VerificationMethod)
		if err != nil {
			return false, err
		}
		if targetVM.MethodType != Secp256k1Key {
			return false, ErrSecp256k1WrongVMType
		}
		return VerifySecp256k1VC(vc, targetVM.BlockchainAccountId)
	case EIP712VCProof:
		targetVM, err := issuerDoc.RetrieveVerificationMethod(proof.VerificationMethod)
		if err != nil {
			return false, err
		}
		if targetVM.MethodType != Secp256k1Key {
			return false, ErrSecp256k1WrongVMType
		}
		return VerifyEIP712VC(vc, bound, targetVM.BlockchainAccountId)
	case Ed25519VCProof:
		targetVM, err := issuerDoc.RetrieveVerificationMethod(proof.VerificationMethod)
		if err != nil {
			return false, err
		}
		if targetVM.MethodType != Ed25519Key {
			return false, ErrEd25519WrongVMType
		}
		return VerifyEd25519VC(vc)
	default:
		return false, ErrUnknownProofType
	}
}

// VerifyVP verifies a verifiable presentation and all credentials within it.
func (c *Client) VerifyVP(presentation *VerifiablePresentation) (bool, error) {
	if err := ParseVPProof(presentation); err != nil {
		return false, err
	}

	chainName, err := GetChainNameFromDID(presentation.Holder)
	if err != nil {
		return false, err
	}
	bound, err := c.GetBoundedContract(chainName)
	if err != nil {
		return false, err
	}

	resolutionMeta, holderDoc, _ := Resolve(presentation.Holder, &ResolutionOptions{}, bound)
	if resolutionMeta.Error != "" {
		return false, errors.New(resolutionMeta.Error)
	}

	var success bool
	switch proof := presentation.Proof.(type) {
	case Secp256k1VPProof:
		targetVM, err := holderDoc.RetrieveVerificationMethod(proof.VerificationMethod)
		if err != nil {
			return false, err
		}
		if targetVM.MethodType != Secp256k1Key {
			return false, ErrSecp256k1WrongVMType
		}
		success, err = VerifySecp256k1VP(presentation, targetVM.BlockchainAccountId)
		if err != nil {
			return false, err
		}
	case EIP712VPProof:
		targetVM, err := holderDoc.RetrieveVerificationMethod(proof.VerificationMethod)
		if err != nil {
			return false, err
		}
		if targetVM.MethodType != Secp256k1Key {
			return false, ErrSecp256k1WrongVMType
		}
		success, err = VerifyEIP712VP(presentation, bound, targetVM.BlockchainAccountId)
		if err != nil {
			return false, err
		}
	case Ed25519VPProof:
		targetVM, err := holderDoc.RetrieveVerificationMethod(proof.VerificationMethod)
		if err != nil {
			return false, err
		}
		if targetVM.MethodType != Ed25519Key {
			return false, ErrEd25519WrongVMType
		}
		success, err = VerifyEd25519VP(presentation)
		if err != nil {
			return false, err
		}
	default:
		return false, ErrUnknownProofType
	}
	if !success {
		return false, err
	}

	for _, credential := range presentation.VerifiableCredential {
		success, err = c.VerifyVC(&credential)
		if !success {
			return false, err
		}
	}

	return true, nil
}
