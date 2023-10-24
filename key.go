package did

import (
	"crypto/ecdsa"
	"encoding/base64"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	gojose "gopkg.in/square/go-jose.v2"
)

// use a private key and a message to create a JWS format signature
func CreateJWSSignature(privKey *ecdsa.PrivateKey, message []byte) (string, error) {
	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.ES256, Key: privKey}, nil)
	if err != nil {
		return "", err
	}
	c := privKey.PublicKey.Curve
	N := c.Params().N

	signature, err := signer.Sign(message)
	if err != nil {
		return "", err
	}

	sBytes := make([]byte, 32)
	copy(sBytes, signature.Signatures[0].Signature[32:])
	var s = new(big.Int).SetBytes(sBytes)

	m := new(big.Int).Div(N, big.NewInt(2))
	q := s.Cmp(m)
	if q > 0 || s.Cmp(big.NewInt(1)) < 0 {
		sub := new(big.Int).Sub(N, s)
		s = new(big.Int).Mod(sub, N)
		newBytes := s.Bytes()
		sByte := make([]byte, 32)
		copy(sByte[32-len(newBytes):], newBytes)
		copy(signature.Signatures[0].Signature[32:], sByte)
	}

	compactserialized, err := signature.DetachedCompactSerialize()
	if err != nil {
		return "", err
	}
	return compactserialized, nil
}

// verify a JWS format signature using the matching public key and the original message
func VerifyJWSSignature(signature string, expectedFullBlkID string, message []byte) (bool, error) {
	partedExpectedBlkID := strings.Split(expectedFullBlkID, ":")
	if (len(partedExpectedBlkID) != 3 && len(partedExpectedBlkID) != 2) || partedExpectedBlkID[0] != "eip155" {
		return false, ErrInvalidBlockID
	}
	partedSig := strings.Split(signature, ".")
	if len(partedSig) != 3 {
		return false, ErrInValidSignature
	}

	sig, err := base64.RawURLEncoding.DecodeString(partedSig[2])
	if err != nil {
		return false, ErrInValidSignature
	}

	decodedPubkey, err := crypto.SigToPub(message[:], sig)
	if err != nil {
		return false, ErrInValidSignature
	}

	decodedBlkID := crypto.PubkeyToAddress(*decodedPubkey).Hex()
	if decodedBlkID != partedExpectedBlkID[len(partedExpectedBlkID)-1] {
		return false, nil
	}
	return true, nil
}

// make sure that the address created from pubKey matches the address stored in vm's BlockChainAccountId field
func CompareAddresses(vm VerificationMethod, pubKey *ecdsa.PublicKey) bool {
	givenAddress := crypto.PubkeyToAddress(*pubKey)
	givenAccountID := "eip155:" + issuerChainId.String() + ":" + givenAddress.Hex()
	if vm.BlockchainAccountId != givenAccountID {
		return false
	}

	return true
}
