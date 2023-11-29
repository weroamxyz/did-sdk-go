### Example Issuer Key:
075a9987addcd8c2e709195533869b8b69eff2d61e345210b687bbc7ab8b66bb
did:metablox:gorli:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A

### Example Presenter Key:
c62ee45278d87e5bdd8b7e895e9de16bfd1a3cbc9ddb7462bf9b30fc7502a3e8
did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665

# Example VC:
## JWS:

### Unsigned VC
```json
{
  "@context": [
    "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#",
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "0",
  "type": [
    "VerifiableCredential",
    "MiningLicense"
  ],
  "issuer": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A",
  "issuanceDate": "2023-11-29T07:20:18Z",
  "expirationDate": "2033-11-29T07:20:18Z",
  "description": "",
  "credentialSubject": {
    "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
    "name": "John Doe",
    "model": "Antminer S19 Pro",
    "serial": "1234567890abcdef"
  },
  "revoked": false
}
```

### JWT For Signing
```json
{"exp":2016861618,"iat":1701242418,"iss":"did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A","jti":"0","sub":"did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665","vc":{"@context":["https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#","https://www.w3.org/2018/credentials/v1"],"credentialSubject":{"id":"did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665","model":"Antminer S19 Pro","name":"John Doe","serial":"1234567890abcdef"},"type":["VerifiableCredential","MiningLicense"]}}
```

### Signed VC
```json
{
  "@context": [
    "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#",
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "0",
  "type": [
    "VerifiableCredential",
    "MiningLicense"
  ],
  "issuer": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A",
  "issuanceDate": "2023-11-29T07:20:18Z",
  "expirationDate": "2033-11-29T07:20:18Z",
  "description": "",
  "credentialSubject": {
    "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
    "name": "John Doe",
    "model": "Antminer S19 Pro",
    "serial": "1234567890abcdef"
  },
  "proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "created": "2023-11-29T07:20:18Z",
    "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
    "proofPurpose": "Authentication",
    "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..8P9LtxB41OyPkNrS_wR8EsXGu9L7YbHG1wRZ_pracN1-ERNLNLP6USMfcfrfpsX_ZVzl6BbipbJlIh89st2l2gE"
  },
  "revoked": false
}
```

## EIP712：
```json
{
  "@context": [
    "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec",
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "0",
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A",
  "issuanceDate": "2023-11-29T01:13:36Z",
  "expirationDate": "2033-11-29T01:13:36Z",
  "description": "",
  "credentialSubject": {
    "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
    "name": "John Doe",
    "model": "Antminer S19 Pro",
    "serial": "1234567890abcdef"
  },
  "proof": {
    "type": "Eip712Signature2021",
    "created": "2023-11-29T01:13:36Z",
    "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
    "proofPurpose": "Authentication",
    "proofValue": "9fcb2518a91f36d70749fafa827dfffba25fce13864c0a66a50f81377450b5ad51d676b8ec4eaec29f6cdd9de3dc43220cd98a779a7c1ba0a2f0813136e9222801"
  },
  "revoked": false
}
```

# Example VP:
## JWS:

### Unsigned VP
```json
{
  "@context": [
    "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#",
    "https://www.w3.org/2018/credentials/v1"
  ],
  "type": [
    "VerifiablePresentation"
  ],
  "verifiableCredential": [
    {
      "@context": [
        "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#",
        "https://www.w3.org/2018/credentials/v1"
      ],
      "id": "0",
      "type": [
        "VerifiableCredential",
        "MiningLicense"
      ],
      "issuer": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A",
      "issuanceDate": "2023-11-29T07:20:18Z",
      "expirationDate": "2033-11-29T07:20:18Z",
      "description": "",
      "credentialSubject": {
        "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
        "name": "John Doe",
        "model": "Antminer S19 Pro",
        "serial": "1234567890abcdef"
      },
      "proof": {
        "type": "EcdsaSecp256k1Signature2019",
        "created": "2023-11-29T07:20:18Z",
        "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
        "proofPurpose": "Authentication",
        "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..8P9LtxB41OyPkNrS_wR8EsXGu9L7YbHG1wRZ_pracN1-ERNLNLP6USMfcfrfpsX_ZVzl6BbipbJlIh89st2l2gE"
      },
      "revoked": false
    }
  ],
  "holder": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665",
  "proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "created": "2023-11-29T15:22:41+08:00",
    "verificationMethod": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665#controller",
    "proofPurpose": "Authentication",
    "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..eGAmRE26etHoCFkPiojSPmuFeiiDiWSnskNlX4arFDZhUwNkf58aeIEOElBLulGnD_cFyterMoUmOQpG-xVIVgE",
    "nonce": "lastBlkNum_audienceAddress"
  }
}
```

### JWT For Signing
```json
{"iat":1701242561,"iss":"did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665","nonce":"lastBlkNum_audienceAddress","vp":{"@context":["https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#","https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"],"verifiableCredential":[{"@context":["https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#","https://www.w3.org/2018/credentials/v1"],"credentialSubject":{"id":"did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665","model":"Antminer S19 Pro","name":"John Doe","serial":"1234567890abcdef"},"description":"","expirationDate":"2033-11-29T07:20:18Z","id":"0","issuanceDate":"2023-11-29T07:20:18Z","issuer":"did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A","proof":{"created":"2023-11-29T07:20:18Z","jws":"eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..8P9LtxB41OyPkNrS_wR8EsXGu9L7YbHG1wRZ_pracN1-ERNLNLP6USMfcfrfpsX_ZVzl6BbipbJlIh89st2l2gE","proofPurpose":"Authentication","type":"EcdsaSecp256k1Signature2019","verificationMethod":"did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller"},"revoked":false,"type":["VerifiableCredential","MiningLicense"]}]}}
```

### Signed VP 
```json
{
  "@context": [
    "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#",
    "https://www.w3.org/2018/credentials/v1"
  ],
  "type": [
    "VerifiablePresentation"
  ],
  "verifiableCredential": [
    {
      "@context": [
        "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#",
        "https://www.w3.org/2018/credentials/v1"
      ],
      "id": "0",
      "type": [
        "VerifiableCredential",
        "MiningLicense"
      ],
      "issuer": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A",
      "issuanceDate": "2023-11-29T07:20:18Z",
      "expirationDate": "2033-11-29T07:20:18Z",
      "description": "",
      "credentialSubject": {
        "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
        "name": "John Doe",
        "model": "Antminer S19 Pro",
        "serial": "1234567890abcdef"
      },
      "proof": {
        "type": "EcdsaSecp256k1Signature2019",
        "created": "2023-11-29T07:20:18Z",
        "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
        "proofPurpose": "Authentication",
        "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..8P9LtxB41OyPkNrS_wR8EsXGu9L7YbHG1wRZ_pracN1-ERNLNLP6USMfcfrfpsX_ZVzl6BbipbJlIh89st2l2gE"
      },
      "revoked": false
    }
  ],
  "holder": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665",
  "proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "created": "2023-11-29T15:22:41+08:00",
    "verificationMethod": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665#controller",
    "proofPurpose": "Authentication",
    "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..eGAmRE26etHoCFkPiojSPmuFeiiDiWSnskNlX4arFDZhUwNkf58aeIEOElBLulGnD_cFyterMoUmOQpG-xVIVgE",
    "nonce": "lastBlkNum_audienceAddress"
  }
}
```
## EIP712:
```json
{
  "@context": [
    "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec",
    "https://www.w3.org/2018/credentials/v1"
  ],
  "type": [
    "VerifiablePresentation"
  ],
  "verifiableCredential": [
    {
      "@context": [
        "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#",
        "https://www.w3.org/2018/credentials/v1"
      ],
      "id": "0",
      "type": [
        "VerifiableCredential",
        "MiningLicense"
      ],
      "issuer": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A",
      "issuanceDate": "2023-11-29T01:12:45Z",
      "expirationDate": "2033-11-29T01:12:45Z",
      "description": "",
      "credentialSubject": {
        "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
        "name": "John Doe",
        "model": "Antminer S19 Pro",
        "serial": "1234567890abcdef"
      },
      "proof": {
        "type": "EcdsaSecp256k1Signature2019",
        "created": "2023-11-29T01:12:45Z",
        "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
        "proofPurpose": "Authentication",
        "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..qXS7DO4eqWbU-CngmJl6PrmxefUzRlyAmYtcsbzIZhwZwuoUjh55-0oa9mK3eo5TqImP2dKMNpHgKpbBSgqBtAE"
      },
      "revoked": false
    }
  ],
  "holder": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665",
  "proof": {
    "type": "Eip712Signature2021",
    "created": "2023-11-29T09:14:34+08:00",
    "verificationMethod": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665#controller",
    "proofPurpose": "Authentication",
    "proofValue": "0cf01fe74adaeedb2bedab5623bcb03a7b9181874527287fbfde8511e45c9fcc4f9f2a08b1263b40c1787a8ce08f42842cc5001723c5e012374e4dad6817ae3001",
    "nonce": "RandomString"
  }
}
```