package did

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestGenerateDIDString(t *testing.T) {
	testKey, err := crypto.HexToECDSA("c62ee45278d87e5bdd8b7e895e9de16bfd1a3cbc9ddb7462bf9b30fc7502a3e8")
	testAddr := crypto.PubkeyToAddress(testKey.PublicKey)
	if err != nil {
		t.Errorf("GenerateDIDString failed: %v", err)
	}
	network := "testnet"

	didString := GenerateDIDString(&testKey.PublicKey, network)
	splitDID := strings.Split(didString, ":")

	if len(didString) == 0 {
		t.Errorf("GenerateDIDString failed: expected non-empty DID string, got empty string")
	}
	if len(splitDID) != 4 {
		t.Errorf("GenerateDIDString failed: expected 4 sections, got %d", len(splitDID))
	}
	if splitDID[0] != "did" || splitDID[1] != "metablox" || splitDID[2] != network || splitDID[3] != testAddr.String() {
		t.Errorf("GenerateDIDString failed: expected ['did', 'metablox', network, address], got %v", splitDID)
	}

}

func TestIsDIDValid(t *testing.T) {
	validDID := []string{"did", "metablox", "1234567890"}
	invalidDID := []string{"did", "metablox"}

	valid := IsDIDValid(validDID)
	invalid := IsDIDValid(invalidDID)

	if !valid {
		t.Errorf("IsDIDValid failed: expected valid DID, got invalid")
	}

	if invalid {
		t.Errorf("IsDIDValid failed: expected invalid DID, got valid")
	}
}

func TestSplitDIDString(t *testing.T) {
	didString := "did:metablox:1234567890"

	splitDID := SplitDIDString(didString)

	if len(splitDID) != 3 {
		t.Errorf("SplitDIDString failed: expected 3 sections, got %d", len(splitDID))
	}

	if splitDID[0] != "did" || splitDID[1] != "metablox" || splitDID[2] != "1234567890" {
		t.Errorf("SplitDIDString failed: expected ['did', 'metablox', '1234567890'], got %v", splitDID)
	}
}

func TestPrepareDID(t *testing.T) {
	testKey, _ := crypto.HexToECDSA("c62ee45278d87e5bdd8b7e895e9de16bfd1a3cbc9ddb7462bf9b30fc7502a3e8")
	testAddr := crypto.PubkeyToAddress(testKey.PublicKey)
	validDID := "did:metablox:testnet:" + testAddr.String()
	invalidDID := "did:metablox"

	validSections, valid := PrepareDID(validDID)
	invalidSections, invalid := PrepareDID(invalidDID)

	if !valid {
		t.Errorf("PrepareDID failed: expected valid DID, got invalid")
	}

	if validSections[0] != "did" || validSections[1] != "metablox" || validSections[2] != "testnet" || validSections[3] != testAddr.String() {
		t.Errorf("PrepareDID failed: expected ['did', 'metablox', '1234567890'], got %v", validSections)
	}

	if invalid {
		t.Errorf("PrepareDID failed: expected invalid DID, got valid, %v", invalidSections)
	}
}
