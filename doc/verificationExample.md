### Example Issuer Key:
075a9987addcd8c2e709195533869b8b69eff2d61e345210b687bbc7ab8b66bb
did:metablox:gorli:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A

9d30fd1e9d81c40bd59fe573ef293485ecf0510809dbf6ef15574ebf9a74f0a03538e21dac0e6ab280ed2614c37cc4a671599dd9794ecf96a7aca0244ccb0d1c
did:metablox:solana:4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts

### Example Presenter Key:
c62ee45278d87e5bdd8b7e895e9de16bfd1a3cbc9ddb7462bf9b30fc7502a3e8
did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665

2043a725ae34fff1fb7eb5057dbc4a585f8b60e98d34dbf6acd3f06d2a78511ee60c01d953de0dea532bad50499d885e7c4320d933df40865a25077fe07151a6
did:metablox:solana:GV1Pc4g468EFW2EEB6N6c4MnMbK9bBCoyEQHpjsH5QCD

### NOTE:
Unix TimeStamp is in second, and the Time Zone is UTC

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
  "issuanceDate": "2023-12-12T15:52:35Z",
  "expirationDate": "2033-12-12T15:52:35Z",
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
{"exp":2018015555,"iat":1702396355,"iss":"did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A","jti":"0","sub":"did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665","vc":{"@context":["https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#","https://www.w3.org/2018/credentials/v1"],"credentialSubject":{"id":"did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665","model":"Antminer S19 Pro","name":"John Doe","serial":"1234567890abcdef"},"description":"","revoked":false,"type":["VerifiableCredential","MiningLicense"]}}
```

Signature creates with Secp256k1Recovery over the Keccak256 Hashed JWT, then encoded in base64

The result Keccak256 Hash of the JWT is:
```
[84 244 110 212 184 235 216 62 245 249 231 251 34 129 69 160 38 119 198 130 236 150 50 18 69 104 63 99 58 56 144 246]
```

The Secp256K1Recovery Signature is:
```
[119 105 251 210 239 183 112 146 153 224 71 230 29 237 160 202 103 233 97 129 89 119 29 28 65 60 242 199 126 171 21 175 55 28 164 78 138 93 177 163 12 146 152 218 169 126 213 69 16 32 215 251 71 115 211 235 246 64 73 174 62 134 204 1 28]
```

The Base64 URL encoded signature is:
```
d2n70u-3cJKZ4EfmHe2gymfpYYFZdx0cQTzyx36rFa83HKROil2xowySmNqpftVFECDX-0dz0-v2QEmuPobMARw
```

The JWS Header is:
```json
{"alg":"ES256K-R","b64":false,"crit":["b64"]}
```

The Full JWS is created by adding the Base64 URL Encoded Header with the signature, here we would ommit the Payload section in the JWS, and creates a compact JWS
```
Base64_Header..Base64_Sig
eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..d2n70u-3cJKZ4EfmHe2gymfpYYFZdx0cQTzyx36rFa83HKROil2xowySmNqpftVFECDX-0dz0-v2QEmuPobMARw
```

Adding the JWS to a 'proof' object into the unsigned VC

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
  "issuanceDate": "2023-12-12T15:52:35Z",
  "expirationDate": "2033-12-12T15:52:35Z",
  "description": "",
  "credentialSubject": {
    "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
    "name": "John Doe",
    "model": "Antminer S19 Pro",
    "serial": "1234567890abcdef"
  },
  "proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "created": "2023-12-12T15:52:35Z",
    "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
    "proofPurpose": "Authentication",
    "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..d2n70u-3cJKZ4EfmHe2gymfpYYFZdx0cQTzyx36rFa83HKROil2xowySmNqpftVFECDX-0dz0-v2QEmuPobMARw"
  },
  "revoked": false
}
```

## Ed25519:

### Unsigned VC:
```json
{
  "@context": [
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "0",
  "type": [
    "VerifiableCredential",
    "MiningLicense"
  ],
  "issuer": "did:metablox:solana:4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts",
  "issuanceDate": "2024-03-19T23:29:03Z",
  "expirationDate": "2034-03-19T23:29:03Z",
  "description": "",
  "credentialSubject": {
    "id": "did:metablox:solana:GV1Pc4g468EFW2EEB6N6c4MnMbK9bBCoyEQHpjsH5QCD",
    "name": "John Doe",
    "model": "Antminer S19 Pro",
    "serial": "1234567890abcdef"
  },
  "revoked": false
}
```

### JWT For Signing:
```json
{"exp":2026423743,"iat":1710890943,"iss":"did:metablox:solana:4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts","jti":"0","sub":"did:metablox:solana:GV1Pc4g468EFW2EEB6N6c4MnMbK9bBCoyEQHpjsH5QCD","vc":{"@context":["https://w3id.org/security/suites/ed25519-2020/v1","https://www.w3.org/2018/credentials/v1"],"credentialSubject":{"id":"did:metablox:solana:GV1Pc4g468EFW2EEB6N6c4MnMbK9bBCoyEQHpjsH5QCD","model":"Antminer S19 Pro","name":"John Doe","serial":"1234567890abcdef"},"description":"","revoked":false,"type":["VerifiableCredential","MiningLicense"]}}
```

Signature creates with Ed25519 over the SHA512 Hashed JWT, then encoded in base64. Notes that Ed25519 algoithmn internally may also performs SHA512 during signing, if not please pass the hash again to get a double-hash before signing.

The result SHA512 Hash of the JWT is:
```
[224 112 251 115 241 115 48 32 246 80 153 114 191 17 163 218 70 246 25 207 148 161 8 63 149 4 169 90 115 116 111 210 58 159 254 84 99 173 39 153 204 0 77 203 249 168 213 136 196 0 39 200 35 33 17 150 219 51 89 61 178 122 37 45]
```

The Ed25519 Signature is:
```
[70 135 208 7 212 104 238 181 107 228 35 124 27 126 128 123 138 17 48 170 111 201 247 0 102 118 232 96 59 224 135 165 27 209 168 47 90 208 246 129 99 246 90 14 9 140 158 87 3 135 108 226 177 196 0 130 0 185 171 183 24 218 49 3]
```

The Base64 URL encoded signature is:
```
RofQB9Ro7rVr5CN8G36Ae4oRMKpvyfcAZnboYDvgh6Ub0agvWtD2gWP2Wg4JjJ5XA4ds4rHEAIIAuau3GNoxAw
```

The JWS Header is:
```json
{"alg":"EdDSA","b64":false,"crit":["b64"]}
```

The Full JWS is created by adding the Base64 URL Encoded Header with the signature, here we would ommit the Payload section in the JWS, and creates a compact JWS
```
Base64_Header..Base64_Sig
eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..RofQB9Ro7rVr5CN8G36Ae4oRMKpvyfcAZnboYDvgh6Ub0agvWtD2gWP2Wg4JjJ5XA4ds4rHEAIIAuau3GNoxAw
```

Adding the JWS to a 'proof' object into the unsigned VC. Notes that a Ed25519 Proof contains the Public Key encoded in Multibase for verification.

### Signed VC:
```json
{
  "@context": [
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "0",
  "type": [
    "VerifiableCredential",
    "MiningLicense"
  ],
  "issuer": "did:metablox:solana:4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts",
  "issuanceDate": "2024-03-19T23:29:03Z",
  "expirationDate": "2034-03-19T23:29:03Z",
  "description": "",
  "credentialSubject": {
    "id": "did:metablox:solana:GV1Pc4g468EFW2EEB6N6c4MnMbK9bBCoyEQHpjsH5QCD",
    "name": "John Doe",
    "model": "Antminer S19 Pro",
    "serial": "1234567890abcdef"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2024-03-19T23:29:03Z",
    "verificationMethod": "did:metablox:solana:4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts#controller",
    "proofPurpose": "Authentication",
    "publicKeyMultibase": "z4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..RofQB9Ro7rVr5CN8G36Ae4oRMKpvyfcAZnboYDvgh6Ub0agvWtD2gWP2Wg4JjJ5XA4ds4rHEAIIAuau3GNoxAw"
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

The nonce is created by joining the current Block Height and the Block Address of the expected audience (Miner Address for Validator VP, and Validator Address for Miner VP)

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
      "issuanceDate": "2023-12-12T15:52:35Z",
      "expirationDate": "2033-12-12T15:52:35Z",
      "description": "",
      "credentialSubject": {
        "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
        "name": "John Doe",
        "model": "Antminer S19 Pro",
        "serial": "1234567890abcdef"
      },
      "proof": {
        "type": "EcdsaSecp256k1Signature2019",
        "created": "2023-12-12T15:52:35Z",
        "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
        "proofPurpose": "Authentication",
        "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..d2n70u-3cJKZ4EfmHe2gymfpYYFZdx0cQTzyx36rFa83HKROil2xowySmNqpftVFECDX-0dz0-v2QEmuPobMARw"
      },
      "revoked": false
    }
  ]
}
```

### JWT For Signing
```json
{"iat":1702396636,"iss":"did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665","nonce":"lastBlkNum_audienceAddress","vp":{"@context":["https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#","https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"],"verifiableCredential":[{"@context":["https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#","https://www.w3.org/2018/credentials/v1"],"credentialSubject":{"id":"did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665","model":"Antminer S19 Pro","name":"John Doe","serial":"1234567890abcdef"},"description":"","expirationDate":"2033-12-12T15:52:35Z","id":"0","issuanceDate":"2023-12-12T15:52:35Z","issuer":"did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A","proof":{"created":"2023-12-12T15:52:35Z","jws":"eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..d2n70u-3cJKZ4EfmHe2gymfpYYFZdx0cQTzyx36rFa83HKROil2xowySmNqpftVFECDX-0dz0-v2QEmuPobMARw","proofPurpose":"Authentication","type":"EcdsaSecp256k1Signature2019","verificationMethod":"did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller"},"revoked":false,"type":["VerifiableCredential","MiningLicense"]}]}}
```

Signature creates with Secp256k1Recovery over the Keccak256 Hashed JWT, then encoded in base64

The result Keccak256 Hash of the JWT is:
```
[62 13 21 24 154 130 140 131 15 9 236 37 18 185 119 76 6 22 210 134 144 236 182 174 219 128 196 2 236 253 3 29]
```

The Secp256K1Recovery Signature is:
```
[192 145 12 240 254 225 29 161 88 139 195 144 228 14 81 22 243 31 47 184 246 94 180 83 31 58 190 176 133 10 53 15 49 176 109 212 236 87 0 182 4 252 225 24 170 197 87 252 10 205 162 210 222 193 153 238 156 173 106 227 229 78 175 137 28]
```

The Base64 URL encoded signature is:
```
wJEM8P7hHaFYi8OQ5A5RFvMfL7j2XrRTHzq-sIUKNQ8xsG3U7FcAtgT84RiqxVf8Cs2i0t7Bme6crWrj5U6viRw
```

The JWS Header is:
```json
{"alg":"ES256K-R","b64":false,"crit":["b64"]}
```

The Full JWS is created by adding the Base64 URL Encoded Header with the signature, here we would ommit the Payload section in the JWS, and creates a compact JWS
```
Base64_Header..Base64_Sig
eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..wJEM8P7hHaFYi8OQ5A5RFvMfL7j2XrRTHzq-sIUKNQ8xsG3U7FcAtgT84RiqxVf8Cs2i0t7Bme6crWrj5U6viRw
```

Adding the JWS to a 'proof' object into the unsigned VP

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
      "issuanceDate": "2023-12-12T15:52:35Z",
      "expirationDate": "2033-12-12T15:52:35Z",
      "description": "",
      "credentialSubject": {
        "id": "did:metablox:gorli:0x53b8702D8621b02B8527E9c0962b1424edabA665",
        "name": "John Doe",
        "model": "Antminer S19 Pro",
        "serial": "1234567890abcdef"
      },
      "proof": {
        "type": "EcdsaSecp256k1Signature2019",
        "created": "2023-12-12T15:52:35Z",
        "verificationMethod": "did:metablox:0x5:0xAf9Aa558f25aB18C9b68AB34C818D659EB56035A#controller",
        "proofPurpose": "Authentication",
        "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..d2n70u-3cJKZ4EfmHe2gymfpYYFZdx0cQTzyx36rFa83HKROil2xowySmNqpftVFECDX-0dz0-v2QEmuPobMARw"
      },
      "revoked": false
    }
  ],
  "holder": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665",
  "proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "created": "2023-12-12T15:57:16Z",
    "verificationMethod": "did:metablox:0x5:0x53b8702D8621b02B8527E9c0962b1424edabA665#controller",
    "proofPurpose": "Authentication",
    "jws": "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..wJEM8P7hHaFYi8OQ5A5RFvMfL7j2XrRTHzq-sIUKNQ8xsG3U7FcAtgT84RiqxVf8Cs2i0t7Bme6crWrj5U6viRw",
    "nonce": "lastBlkNum_audienceAddress"
  }
}
```

## Ed25519:

### Unsigned VP:
```json
{
  "@context": [
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://www.w3.org/2018/credentials/v1"
  ],
  "type": [
    "VerifiablePresentation"
  ],
  "verifiableCredential": [
    {
      "@context": [
        "https://w3id.org/security/suites/ed25519-2020/v1",
        "https://www.w3.org/2018/credentials/v1"
      ],
      "id": "0",
      "type": [
        "VerifiableCredential",
        "MiningLicense"
      ],
      "issuer": "did:metablox:solana:4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts",
      "issuanceDate": "2024-03-19T23:40:16Z",
      "expirationDate": "2034-03-19T23:40:16Z",
      "description": "",
      "credentialSubject": {
        "id": "did:metablox:solana:GV1Pc4g468EFW2EEB6N6c4MnMbK9bBCoyEQHpjsH5QCD",
        "name": "John Doe",
        "model": "Antminer S19 Pro",
        "serial": "1234567890abcdef"
      },
      "proof": {
        "type": "Ed25519Signature2020",
        "created": "2024-03-19T23:40:16Z",
        "verificationMethod": "did:metablox:solana:4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts#controller",
        "proofPurpose": "Authentication",
        "publicKeyMultibase": "z4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..mJI1VU3qWMgGv-YO01iiWxIK_z6QRCwoExR1ztI53jdn9c4KOdNOrb1bD5wQr-5GO2N9_AOE-yozg8jpPGmdBQ"
      },
      "revoked": false
    }
  ],
  "holder": "did:metablox:solana:GV1Pc4g468EFW2EEB6N6c4MnMbK9bBCoyEQHpjsH5QCD"
}
```

### JWT For Signing:
```json
{"iat":1710891649,"iss":"did:metablox:solana:GV1Pc4g468EFW2EEB6N6c4MnMbK9bBCoyEQHpjsH5QCD","nonce":"lastBlkNum_audienceAddress","vp":{"@context":["https://w3id.org/security/suites/ed25519-2020/v1","https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"],"verifiableCredential":[{"@context":["https://w3id.org/security/suites/ed25519-2020/v1","https://www.w3.org/2018/credentials/v1"],"credentialSubject":{"id":"did:metablox:solana:GV1Pc4g468EFW2EEB6N6c4MnMbK9bBCoyEQHpjsH5QCD","model":"Antminer S19 Pro","name":"John Doe","serial":"1234567890abcdef"},"description":"","expirationDate":"2034-03-19T23:40:16Z","id":"0","issuanceDate":"2024-03-19T23:40:16Z","issuer":"did:metablox:solana:4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts","proof":{"created":"2024-03-19T23:40:16Z","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..mJI1VU3qWMgGv-YO01iiWxIK_z6QRCwoExR1ztI53jdn9c4KOdNOrb1bD5wQr-5GO2N9_AOE-yozg8jpPGmdBQ","proofPurpose":"Authentication","publicKeyMultibase":"z4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts","type":"Ed25519Signature2020","verificationMethod":"did:metablox:solana:4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts#controller"},"revoked":false,"type":["VerifiableCredential","MiningLicense"]}]}}
```

Signature creates with Ed25519 over the SHA512 Hashed JWT, then encoded in base64. Notes that Ed25519 algoithmn internally may also performs SHA512 during signing, if not please pass the hash again to get a double-hash before signing.

The result SHA512 Hash of the JWT is:
```
[5 119 177 144 34 86 249 141 102 49 249 76 35 227 28 11 82 38 170 246 78 77 200 47 74 191 155 120 65 112 53 253 157 40 75 141 63 45 241 191 244 22 29 171 133 33 65 210 75 36 174 155 129 144 173 150 211 12 199 80 198 181 143 242]
```

The Ed25519 Signature is:
```
[2 181 27 206 98 45 166 217 162 116 100 81 156 252 180 17 186 27 133 45 238 64 130 84 198 54 118 220 243 227 111 225 169 187 12 190 51 26 157 116 36 72 192 62 3 87 130 75 148 198 221 199 109 111 141 150 239 248 126 255 41 121 209 11]
```

The Base64 URL encoded signature is:
```
ArUbzmItptmidGRRnPy0EbobhS3uQIJUxjZ23PPjb-Gpuwy-MxqddCRIwD4DV4JLlMbdx21vjZbv-H7_KXnRCw
```

The JWS Header is:
```json
{"alg":"EdDSA","b64":false,"crit":["b64"]}
```

The Full JWS is created by adding the Base64 URL Encoded Header with the signature, here we would ommit the Payload section in the JWS, and creates a compact JWS
```
Base64_Header..Base64_Sig
eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..ArUbzmItptmidGRRnPy0EbobhS3uQIJUxjZ23PPjb-Gpuwy-MxqddCRIwD4DV4JLlMbdx21vjZbv-H7_KXnRCw
```

Adding the JWS to a 'proof' object into the unsigned VC. Notes that a Ed25519 Proof contains the Public Key encoded in Multibase for verification.

### Signed VP:
```json
{
  "@context": [
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://www.w3.org/2018/credentials/v1"
  ],
  "type": [
    "VerifiablePresentation"
  ],
  "verifiableCredential": [
    {
      "@context": [
        "https://w3id.org/security/suites/ed25519-2020/v1",
        "https://www.w3.org/2018/credentials/v1"
      ],
      "id": "0",
      "type": [
        "VerifiableCredential",
        "MiningLicense"
      ],
      "issuer": "did:metablox:solana:4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts",
      "issuanceDate": "2024-03-19T23:40:16Z",
      "expirationDate": "2034-03-19T23:40:16Z",
      "description": "",
      "credentialSubject": {
        "id": "did:metablox:solana:GV1Pc4g468EFW2EEB6N6c4MnMbK9bBCoyEQHpjsH5QCD",
        "name": "John Doe",
        "model": "Antminer S19 Pro",
        "serial": "1234567890abcdef"
      },
      "proof": {
        "type": "Ed25519Signature2020",
        "created": "2024-03-19T23:40:16Z",
        "verificationMethod": "did:metablox:solana:4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts#controller",
        "proofPurpose": "Authentication",
        "publicKeyMultibase": "z4akv7rKw4raUAg22uozxxf2AP2G9VPno8xLRpAJpbxts",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..mJI1VU3qWMgGv-YO01iiWxIK_z6QRCwoExR1ztI53jdn9c4KOdNOrb1bD5wQr-5GO2N9_AOE-yozg8jpPGmdBQ"
      },
      "revoked": false
    }
  ],
  "holder": "did:metablox:solana:GV1Pc4g468EFW2EEB6N6c4MnMbK9bBCoyEQHpjsH5QCD",
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2024-03-19T23:40:49Z",
    "verificationMethod": "did:metablox:solana:GV1Pc4g468EFW2EEB6N6c4MnMbK9bBCoyEQHpjsH5QCD#controller",
    "proofPurpose": "Authentication",
    "publicKeyMultibase": "zGV1Pc4g468EFW2EEB6N6c4MnMbK9bBCoyEQHpjsH5QCD",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..ArUbzmItptmidGRRnPy0EbobhS3uQIJUxjZ23PPjb-Gpuwy-MxqddCRIwD4DV4JLlMbdx21vjZbv-H7_KXnRCw",
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