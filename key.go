package did

import (
	"bytes"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/crypto"
	gojose "gopkg.in/square/go-jose.v2"
	"math/big"
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
func VerifyJWSSignature(signature string, pubKey *ecdsa.PublicKey, message []byte) (bool, error) {
	sigObject, err := gojose.ParseDetached(signature, message)
	if err != nil {
		return false, err
	}

	result, err := sigObject.Verify(pubKey)
	if err != nil {
		return false, err
	}

	if !bytes.Equal(message, result) {
		return false, nil
	} else {
		return true, nil
	}
}

// make sure that the address created from pubKey matches the address stored in vm's BlockChainAccountId field
func CompareAddresses(vm VerificationMethod, pubKey *ecdsa.PublicKey) bool {
	givenAddress := crypto.PubkeyToAddress(*pubKey)
	givenAccountID := "eip155:1666600000:" + givenAddress.Hex()
	if vm.BlockchainAccountId != givenAccountID {
		return false
	}

	return true
}
