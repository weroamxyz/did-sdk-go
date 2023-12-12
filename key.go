package did

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// use a private key and a message to create a JWS format signature
func CreateJWSSignature(privKey *ecdsa.PrivateKey, message []byte) (string, error) {
	/*
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
	*/

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256K-R","b64":false,"crit":["b64"]}`))

	// Replace the Signature with the SECP256k1r signature
	sig, err := crypto.Sign(message[:], privKey)
	if err != nil {
		return "", err
	}

	// Manually calaulate the V byte by adding 27 to the recovery ID
	sig[64] += 27

	encodedSig := base64.RawURLEncoding.EncodeToString(sig)
	compactserialized := header + "." + "." + encodedSig

	return compactserialized, nil
}

// verify a JWS format signature using the matching public key and the original message
func VerifyJWSSignature(signature string, expectedFullBlkID string, message []byte) (bool, error) {
	partedExpectedBlkID := strings.Split(expectedFullBlkID, ":")
	if (len(partedExpectedBlkID) != 3 && len(partedExpectedBlkID) != 2) || partedExpectedBlkID[0] != "eip155" {
		return false, ErrInvalidBlockID
	}
	expectedAddress := partedExpectedBlkID[len(partedExpectedBlkID)-1]

	partedSig := strings.Split(signature, ".")
	if len(partedSig) != 3 {
		return false, ErrInValidSignature
	}

	sig, err := base64.RawURLEncoding.DecodeString(partedSig[2])
	if err != nil {
		return false, ErrInValidSignature
	}

	// Manually calaulate the Recovery ID by subtracting 27 from the V byte
	if len(sig) != 65 {
		return false, ErrInValidSignature
	}

	if sig[64] != 0x00 && sig[64] != 0x01 {
		sig[64] -= 27
	}

	recoveredPubKey, err := crypto.SigToPub(message[:], sig)
	if err != nil {
		return false, ErrInValidSignature
	}

	recoveredAddress := crypto.PubkeyToAddress(*recoveredPubKey).Hex()
	return recoveredAddress == expectedAddress, nil
}

// Function to verify an Ethereum EIP-712 signature
func VerifyEIP712Signature(signature string, expectedFullBlkID string, message []byte) (bool, error) {

	partedExpectedBlkID := strings.Split(expectedFullBlkID, ":")
	if (len(partedExpectedBlkID) != 3 && len(partedExpectedBlkID) != 2) || partedExpectedBlkID[0] != "eip155" {
		return false, ErrInvalidBlockID
	}

	expectedAddress := partedExpectedBlkID[len(partedExpectedBlkID)-1]

	// Parse the signature
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false, err
	}
	if len(sig) != 65 {
		return false, errors.New("invalid signature length")
	}
	/*
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:64])
		v := sig[64]
	*/

	// Recover the public key
	recoveredPubKey, err := crypto.SigToPub(message, sig)
	if err != nil {
		return false, err
	}

	// Compute the address
	recoveredAddress := crypto.PubkeyToAddress(*recoveredPubKey).Hex()

	// Compare the addresses
	return recoveredAddress == expectedAddress, nil
}

func CreateEIP712Signature(privKey *ecdsa.PrivateKey, typedDataHash common.Hash) (string, error) {

	signature, err := crypto.Sign(typedDataHash.Bytes(), privKey)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(signature), nil
}

// Function to compare two Ethereum addresses by checking the identifiers and chainIDs
func CompareAddresses(address1 string, address2 string) bool {
	// Parse the addresses
	parsedAddress1 := strings.Split(address1, ":")
	parsedAddress2 := strings.Split(address2, ":")
	if len(parsedAddress1) == len(parsedAddress2) {
		return address1 == address2
	}

	// Check the identifiers
	if parsedAddress1[0] != parsedAddress2[0] {
		return false
	}

	// Check the chainIDs
	if parsedAddress1[1] != parsedAddress2[1] {
		return false
	}

	// Check the addresses
	if parsedAddress1[2] != parsedAddress2[2] {
		return false
	}

	return true
}
