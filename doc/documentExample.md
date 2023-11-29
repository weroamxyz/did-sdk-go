## MetaBlox DID

### Default DID Document （Harmony Mainnet）

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/secp256k1recovery-2020/v2"
  ],
  "id": "did:metablox:harmony:0x1234567890ABCDEFGHIJ1234567890ABCDEFGHIJ",
  "verificationMethod": [
    {
      "id": "did:metablox:harmony:0x1234567890ABCDEFGHIJ1234567890ABCDEFGHIJ#controller",
      "type": "EcdsaSecp256k1RecoveryMethod2020",
      "controller": "did:metablox:harmony:0x1234567890ABCDEFGHIJ1234567890ABCDEFGHIJ",
      "blockchainAccountId": "eip155:0x63768244:0x1234567890ABCDEFGHIJ1234567890ABCDEFGHIJ"
    }
  ],
  "authentication": [ "did:metablox:harmony:0x1234567890ABCDEFGHIJ1234567890ABCDEFGHIJ#controller" ],
  "assertionMethod": [ "did:metablox:harmony:0x1234567890ABCDEFGHIJ1234567890ABCDEFGHIJ#controller"
  ]
}
```

Note： Harmony Mainnet DID can also be:
`did:metablox:0x63768244:0x1234567890ABCDEFGHIJ1234567890ABCDEFGHIJ`
0x63768244 is the chainID 1666600000 in HEX

### VC Demo (Harmony Mainnet)

```JSON
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
   "id": "http://metablox.io/credentials/123", 
  "type": [
    "VerifiableCredential","WifiAccessCredential"
  ],
  "issuer":"did:metablox:harmony:0xABCDEFGHIJABCDEFGHIJ12345678901234567890", 
  "issuanceDate": "2023-01-01T19:73:24Z",
  "expirationDate": "2025-01-01T19:73:24Z",
  "credentialSubject": {
    "id": "did:metablox:harmony:0x1234567890ABCDEFGHIJ1234567890ABCDEFGHIJ",
    "type": "Validator" // Validator,Miner
  },
    "proof": {
        "type": "EcdsaSecp256k1RecoverySignature2020",
        "created": "2023-10-19T03:29:57Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:metablox:harmony:0x1234567890ABCDEFGHIJ1234567890ABCDEFGHIJ#controller",
        "jws": "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhb..."
    },
     "revoked": false
}
```

### VP Demo (Harmony Mainnet)

```json
{
  "@context": [
    "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#",
    "https://www.w3.org/2018/credentials/v1"
  ],
  "type": ["VerifiablePresentation"],
  "verifiableCredential": [
    {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "id": "http://metablox.io/credentials/123", 
      "type": ["VerifiableCredential", "WifiAccessCredential"],
      "issuer": "did:metablox:harmony:0xABCDEFGHIJABCDEFGHIJ12345678901234567890", 
      "issuanceDate": "2023-01-01T19:73:24Z",
      "expirationDate": "2025-01-01T19:73:24Z",
      "credentialSubject": {
        "id": "did:metablox:harmony:0x1234567890ABCDEFGHIJ1234567890ABCDEFGHIJ",
        "type": "Validator" // Validator,Miner
      },
      "proof": {
        "type": "EcdsaSecp256k1RecoverySignature2020",
        "created": "2023-10-19T03:29:57Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:metablox:harmony:0x1234567890ABCDEFGHIJ1234567890ABCDEFGHIJ#controller",
        "jws": "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhb..."
      },
      "revoked": false
    }
  ],
  "holder": "did:metablox:harmony:0x1234567890ABCDEFGHIJ1234567890ABCDEFGHIJ",
  "proof": {
    "type": "EcdsaSecp256k1RecoverySignature2020",
    "created": "2023-10-19T05:29:57Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:metablox:harmony:0x1234567890ABCDEFGHIJ1234567890ABCDEFGHIJ#controller",
    "jws": "sssseyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhb..."
  }
}
```
# Proof Types

Currently we supports two methods of proof types, EcdsaSecp256k1Signature2019 in JWT and EIP712

## VC

### JWS:
The JWS is calculated by converting the VC document into a JWT first, mapping and adding all the corresponding fields. The JWT is canonicalized so the result Hash could be deterministic.

Original Document:
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
  "issuanceDate": "2023-11-28T17:18:22Z",
  "expirationDate": "2033-11-28T17:18:22Z",
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

JWT:
```json
{
  "exp": 2016811102, // The Unix Timestamp of the VC Expiration Date
  "iat": 1701191902, // The Unix Timestamp of the VC Issurance Date
  "iss": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A",
  "jti": "0",
  "sub": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
  "vc": {
    "@context": [
      "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#",
      "https://www.w3.org/2018/credentials/v1"
    ],
    "credentialSubject": {
      "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
      "model": "Antminer S19 Pro",
      "name": "John Doe",
      "serial": "1234567890abcdef"
    },
    "type": [
      "VerifiableCredential",
      "MiningLicense"
    ]
  }
}
```
After obtaining the Canonicalized JWT, the JWS is calculated with the SHA256 Hash of the JWT, and the Issuer's Private Key, with the Secp256k1Recovery algorithm. Note that in the header, we uses
```json
{"alg":"ES256K-R","b64":false,"crit":["b64"]}
```
The signature and header are Base 64 encoded, leaving the payload omitted. 

Resulting Proof is as followd.
```json
"proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "created": "2023-11-28T17:18:22Z",
    "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
    "proofPurpose": "Authentication",
    "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..unmMtYudrPyNMRcLxwaV4-mSwfzTVOVT836rmjwAfGg4fzRpj_F-eE9pvwehqHPGu5zZgwKHD3YTaZ2o8vn1hwE"
}
```

### EIP712:
The defined EIP712 Types for VC is as below,
```json
{
    "EIP712Domain": {
        {"Name": "name", "Type": "string"},
        {"Name": "version", "Type": "string"},
        {"Name": "chainId", "Type": "uint256"},
        {"Name": "verifyingContract", "Type": "address"},
    },
    "VerifiableCredential": {
        {"Name": "@context", "Type": "string[]"},
        {"Name": "id", "Type": "string"},
        {"Name": "type", "Type": "string[]"},
        {"Name": "issuer", "Type": "string"},
        {"Name": "credentialSubjectData", "Type": "bytes"},
        {"Name": "issuanceDate", "Type": "string"},
        {"Name": "expirationDate", "Type": "string"},
        {"Name": "revoked", "Type": "bool"},
    }
}
```
The EIP712 Doamin Seperator Name is "EIP712Verifiable", Primary Type is "VerifiableCredential", and the "credentialSubjectData" is the Keccak256 Hash for the Canonicalized JSON of Credential Subject.
Please refer to https://eips.ethereum.org/EIPS/eip-712

After obtaining the Keccak256 Hash of the EIP712 Message, it is signed with the Issuer's Private Key.

Below is the result EIP712 Proof
```json
"proof": {
    "type": "Eip712Signature2021",
    "created": "2023-11-28T17:48:32Z",
    "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
    "proofPurpose": "Authentication",
    "proofValue": "8a115b85f9fdbdb138a91a1e9036159cb5a1a74ff9108349f4d709eb054f8ac04924e150452cba9f16a573136a708acb1f571675da347dd4d50734a2c3ff4bc801"
}
```
Full Document:
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
  "issuanceDate": "2023-11-28T17:48:32Z",
  "expirationDate": "2033-11-28T17:48:32Z",
  "description": "",
  "credentialSubject": {
    "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
    "name": "John Doe",
    "model": "Antminer S19 Pro",
    "serial": "1234567890abcdef"
  },
  "proof": {
    "type": "Eip712Signature2021",
    "created": "2023-11-28T17:48:32Z",
    "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
    "proofPurpose": "Authentication",
    "proofValue": "8a115b85f9fdbdb138a91a1e9036159cb5a1a74ff9108349f4d709eb054f8ac04924e150452cba9f16a573136a708acb1f571675da347dd4d50734a2c3ff4bc801"
  },
  "revoked": false
}
```

## VP
### JWS
VP is generated similiar to VC, first we would transform the VP document into a JWT, then use the SHA256 Hash of the Canonicalied JWT to calculate the JWS

Original Document:
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
      "issuanceDate": "2023-11-28T17:48:30Z",
      "expirationDate": "2033-11-28T17:48:30Z",
      "description": "",
      "credentialSubject": {
        "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
        "name": "John Doe",
        "model": "Antminer S19 Pro",
        "serial": "1234567890abcdef"
      },
      "proof": {
        "type": "EcdsaSecp256k1Signature2019",
        "created": "2023-11-28T17:48:30Z",
        "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
        "proofPurpose": "Authentication",
        "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..p86PMPsf9RDtw3jON84bhx40589x-QpswBF4O87WPOQvxZeHPHTvz6_ilHURjKE9B1cR4a2hokwpl5aTE9hGUQA"
      },
      "revoked": false
    }
  ],
  "holder": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665"
}
```

JWT:
```json
{
  "iat": 1701193720,
  "iss": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665",
  "nonce": "RandomString",
  "vp": {
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
        "credentialSubject": {
          "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
          "model": "Antminer S19 Pro",
          "name": "John Doe",
          "serial": "1234567890abcdef"
        },
        "description": "",
        "expirationDate": "2033-11-28T17:48:30Z",
        "id": "0",
        "issuanceDate": "2023-11-28T17:48:30Z",
        "issuer": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A",
        "proof": {
          "created": "2023-11-28T17:48:30Z",
          "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..p86PMPsf9RDtw3jON84bhx40589x-QpswBF4O87WPOQvxZeHPHTvz6_ilHURjKE9B1cR4a2hokwpl5aTE9hGUQA",
          "proofPurpose": "Authentication",
          "type": "EcdsaSecp256k1Signature2019",
          "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller"
        },
        "revoked": false,
        "type": [
          "VerifiableCredential",
          "MiningLicense"
        ]
      }
    ]
  }
}
```

The result:
```json
"proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "created": "2023-11-29T01:48:40+08:00",
    "verificationMethod": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665#controller",
    "proofPurpose": "Authentication",
    "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..EmDRLjJTK4p8QTB0RY17tqFRt3UM4R-bKWsJooHy6zlegUklLz98ypFmueeq_sC6XRdT4IB52Uphj_dMNLUliwE",
    "nonce": "RandomString"
}
```

### EIP712:
Similiar to the VC, we have defined the EIP712 struct as well.
he EIP712 Doamin Seperator Name is "EIP712Verifiable", Primary Type is "VerifiablePresentation".
The "verifiableCredentialData" is the Keccak256 Hash for the Canonicalized JSON of Verifiable Credential Array.
```json
{
    "EIP712Domain": {
        {"Name": "name", "Type": "string"},
        {"Name": "version", "Type": "string"},
        {"Name": "chainId", "Type": "uint256"},
        {"Name": "verifyingContract", "Type": "address"},
    },
    "VerifiablePresentation": {
        {"Name": "@context", "Type": "string[]"},
        {"Name": "type", "Type": "string[]"},
        {"Name": "holder", "Type": "string"},
        {"Name": "verifiableCredentialData", "Type": "bytes"},
    }
}
```
And the result:
```json
"proof": {
    "type": "Eip712Signature2021",
    "created": "2023-11-29T01:51:22+08:00",
    "verificationMethod": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665#controller",
    "proofPurpose": "Authentication",
    "proofValue": "339b8c343323d6ae325a82669ec1be2bb42bcb1e6181bff113e813323d0a81df279175d1e34a07c9ca671b49cdf7c8fe5bfd5f5fb8ca51825d7660f120ec27ff00",
    "nonce": "RandomString"
  }
```

Full Document:
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
      "issuanceDate": "2023-11-28T17:48:30Z",
      "expirationDate": "2033-11-28T17:48:30Z",
      "description": "",
      "credentialSubject": {
        "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
        "name": "John Doe",
        "model": "Antminer S19 Pro",
        "serial": "1234567890abcdef"
      },
      "proof": {
        "type": "EcdsaSecp256k1Signature2019",
        "created": "2023-11-28T17:48:30Z",
        "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
        "proofPurpose": "Authentication",
        "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..p86PMPsf9RDtw3jON84bhx40589x-QpswBF4O87WPOQvxZeHPHTvz6_ilHURjKE9B1cR4a2hokwpl5aTE9hGUQA"
      },
      "revoked": false
    }
  ],
  "holder": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665",
  "proof": {
    "type": "Eip712Signature2021",
    "created": "2023-11-29T01:51:22+08:00",
    "verificationMethod": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665#controller",
    "proofPurpose": "Authentication",
    "proofValue": "339b8c343323d6ae325a82669ec1be2bb42bcb1e6181bff113e813323d0a81df279175d1e34a07c9ca671b49cdf7c8fe5bfd5f5fb8ca51825d7660f120ec27ff00",
    "nonce": "RandomString"
  }
}
```

