package did

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateVCSecp256k1Proof(t *testing.T) {
	vm := "secp256k1"
	result := CreateVCSecp256k1Proof(vm)
	assert.NotNil(t, result)
}

func TestCreateVCEIP712Proof(t *testing.T) {
	vm := "eip712"
	result := CreateVCEIP712Proof(vm)
	assert.NotNil(t, result)
}

func TestConvertTimesFromDBFormat(t *testing.T) {
	vc := &VerifiableCredential{}
	err := ConvertTimesFromDBFormat(vc)
	assert.NoError(t, err)
}

func TestConvertTimesToDBFormat(t *testing.T) {
	vc := &VerifiableCredential{}
	err := ConvertTimesToDBFormat(vc)
	assert.NoError(t, err)
}

func TestVCToJson(t *testing.T) {
	vc := &VerifiableCredential{}
	result, err := VCToJson(vc)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestJsonToVC(t *testing.T) {
	jsonVC := []byte(`{"id": "123"}`)
	result, err := JsonToVC(jsonVC)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}
