## Trust Your Supplier – DID Specification Document



**Source**: Chainyard (An IT People Company) – 1 Copley Parkway, Morrisville, NC, 27560 USA

**Website**: www.chainyard.com, www.trustyoursupplier.com

**Authors**:  Mohan Venkataraman, Pawan Pandey

**Editors**: Shyam Adivi, Sree Mudundi, Gary Storr

**Date**: 04/19/2019

**Status**: DRAFT V0.4

<br/><br/><br/><br/>

#### Contents

[About TYS](https://github.com/pawan-cy/tys/blob/master/README.md#about-tys)

[Method Name](https://github.com/pawan-cy/tys/blob/master/README.md#method-name)

[Method Specific Identifiers](https://github.com/pawan-cy/tys/blob/master/README.md#method-specific-identifiers)

[Generating a unique idstring](https://github.com/pawan-cy/tys/blob/master/README.md#generating-a-unique-idstring)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Test Results](https://github.com/pawan-cy/tys/blob/master/README.md#test-results)

[TYS DIDs](https://github.com/pawan-cy/tys/blob/master/README.md#tys-dids)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[TYS DID Example](https://github.com/pawan-cy/tys/blob/master/README.md#tys-did-example)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[TYS DID Document (Organization)](https://github.com/pawan-cy/tys/blob/master/README.md#tys-did-document-organization)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Example 1](https://github.com/pawan-cy/tys/blob/master/README.md#example-1)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Example 2](https://github.com/pawan-cy/tys/blob/master/README.md#example-2)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[TYS DID Document (Claim)](https://github.com/pawan-cy/tys/blob/master/README.md#tys-did-document-claim)<br/>

[DID Transaction Process Flow](https://github.com/pawan-cy/tys/blob/master/README.md#did-transaction-process-flow)

[TYS Functions](https://github.com/pawan-cy/tys/blob/master/README.md#tys-functions)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Create and Register a DID](https://github.com/pawan-cy/tys/blob/master/README.md#create-and-register-a-did)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Read](https://github.com/pawan-cy/tys/blob/master/README.md#read)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Update](https://github.com/pawan-cy/tys/blob/master/README.md#update)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Deactivate](https://github.com/pawan-cy/tys/blob/master/README.md#deactivate)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[GetAllCredentialsForEntity](https://github.com/pawan-cy/tys/blob/master/README.md#getallcredentialsforentity)<br/>

[Status](https://github.com/pawan-cy/tys/blob/master/README.md#status)

[References](https://github.com/pawan-cy/tys/blob/master/README.md#references)

<br/><br/><br/><br/>

#### About TYS
“Trust Your Supplier” aka “TYS”  is actively in development at Chainyard, a leading Blockchain development firm located in RTP North Carolina. The network is undergoing beta testing and will go live in the next couple of months.

The TYS network is a cross industry source of supplier information and identity helping to simplify and accelerate the onboarding and lifecycle management process. TYS is a fit-for-purpose blockchain optimized for sharing supplier credentials in a supply chain environment. TYS DIDs may be used by Suppliers, Buyers, Verifiers, Banks and other organizations to establish identities for verifiable claims made by any party.

TYS is implemented on Hyperledger Fabric, a permissioned blockchain technology under the Linux Foundation’s Hyperledger Project.  The “Smart Contract” Functions are written in “Golang” and all client APIs are provided as REST APIs written in “Javascript” running on “NodeJS.

This document specifies the “Trust Your Supplier” [DID Method](https://w3c-ccg.github.io/did-spec/#specific-did-method-schemes) [did:tys].

This specification conforms to the requirements specified in the DID specification currently published by the W3C Credentials Community Group. For more information about DIDs and DID method specifications, please see [DID Primer](https://github.com/WebOfTrustInfo/rwot5-boston/blob/master/topics-and-advance-readings/did-primer.md) and [DID Specification](https://w3c-ccg.github.io/did-spec/).

###### TYS Security
TYS as an application supports authentication and authorization schemes based on certificates issued by the network Certificate Authority. It also supports multi-factor authentication. TYS transactions are executed by smart contracts that are based on business rules and policies. If a particular policy requires re-authentication, the specific smart contract function will address those needs. Key management services are provided by cloud based HSMs. The TYS ledger currently uses the “Kafka” based ordering service for consensus. It will soon be transitioned to the modified version of the RAFT protocol supported by the Hyperledger Fabric as its consensus algorithm when generally available.

All user interactions with TYS are logged for auditability. The application restricts a user to have only a single session at any given time.

#### Method Name
The "namestring" that shall identify this DID method is: **tys**.

A DID that uses this method **MUST** begin with the following prefix: did:tys: . Per the DID specification, this prefix MUST be in lowercase. The format of remainder of the DID, after this prefix, is specified below in the section on [Method Specific Identifiers](https://github.com/ockam-network/did-method-spec/blob/master/README.md#method-specific-identifiers).

#### Method Specific Identifiers
TYS DIDs will conform with [the Generic DID Scheme](https://w3c-ccg.github.io/did-spec/#the-generic-did-scheme) described in the DID spec. The format of the tys-specific-idstring is described below in [ABNF](https://tools.ietf.org/html/rfc5234):

```
scala
tys-did               = "did:tys:" tys-specific-idstring

idstring                = 40*HEXDIG (base58 encoded)
base58char              = "1" / "2" / "3" / "4" / "5" / "6" / "7" / "8" / "9" / "A" / "B" / "C"
                          / "D" / "E" / "F" / "G" / "H" / "J" / "K" / "L" / "M" / "N" / "P" / "Q"
                          / "R" / "S" / "T" / "U" / "V" / "W" / "X" / "Y" / "Z" / "a" / "b" / "c"
                          / "d" / "e" / "f" / "g" / "h" / "i" / "j" / "k" / "m" / "n" / "o" / "p"
                          / "q" / "r" / "s" / "t" / "u" / "v" / "w" / "x" / "y" / "z"
```

#### Generating a unique idstring
A unique idstring is created as follows:
1. Generate a public/private keypair, using one of the methods in the [Linked Data Cryptographic Suite Registry](https://w3c-ccg.github.io/ld-cryptosuite-registry/).
2. Hash the public key from step 1 using one of the hashing algorithms supported by [multihash](https://multiformats.io/multihash/).
3. Truncate the hash from step 2 to the lower 20 bytes – This will be compatible with account IDs in Ethereum and other blockchains.
4. The [multihash prefix](https://github.com/multiformats/multicodec/blob/master/table.csv) for the algorithm chosen in step 2  and the length are not included in the current version. Currently the algorithm (0x12) and the length (0x14) part of a multihash is not included because length of the hashed value is always 20 bytes per step 3 and the hash algorithm is sha2-256.
5. [Base58](https://en.wikipedia.org/wiki/Base58) encode the value from step 4 using the [Bitcoin alphabet](https://en.bitcoinwiki.org/wiki/Base58#Alphabet_Base58).

The following Golang code illustrates this process of generating a unique TYS DID. This code will be part of the identity smart contract within the TYS Network. The random seed will be generated externally and passed in as a transient payload.

```go
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/btcsuite/btcutil/base58"
	"fmt"
	"os"
)

func main() {

	// ECDSA Elliptical Curve Pub/Private Keys
	pubkeyCurve := elliptic.P256() //see http://golang.org/pkg/crypto/elliptic/#P256

	prKey := new(ecdsa.PrivateKey)
	prKey, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader) // this generates a public & private key pair

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var pukey ecdsa.PublicKey
	pukey = prKey.PublicKey
	pubKeyStr := pukey.X.String()+pukey.Y.String()
	pubKeyHex := fmt.Sprintf("%x%x", pukey.X, pukey.Y)

	// Generate Base58 Encoded DID
	sum := sha256.Sum256([]byte(pubKeyHex))
	sum_base58 := base58.Encode(sum[0:20])
	tys_did_base58enc := fmt.Sprintf("did:tys:"+ sum_base58)

	// Generate standard unencoded DID
	tys_did := fmt.Sprintf("did:tys:%x", sum[0:20])

	fmt.Println("Private Key :")
	fmt.Printf("%d \n", prKey)

	fmt.Println()
	fmt.Println("Public Key :")
	fmt.Printf("%d \n", pukey)
	fmt.Printf("%s \n", pubKeyStr)
	fmt.Printf("%s \n", pubKeyHex );

	fmt.Println()
	fmt.Println("hash of Public Key  in HEX:")
	fmt.Printf("%x \n", sum)

	fmt.Println()
	fmt.Println("First 20 Bytes in HEX")
	fmt.Printf("%x \n", sum[0:20])

	fmt.Println()
	fmt.Println("DID in Base58 Encoding and without Encoding")
	fmt.Println(tys_did_base58enc)
	fmt.Println(tys_did)
}
```
##### Test Results


**Private Key :**
```
&{{{842350552256} 22001963804334027204127086025456691471972245705670468283780584265832903672895 68783280147399643216889661967638391658473045558227023134602849600796510992165} 84402287888165422353075677022858628482056011430115186165685582319392847963632}
```

**Public Key :**
```
{{842350552256} 22001963804334027204127086025456691471972245705670468283780584265832903672895 68783280147399643216889661967638391658473045558227023134602849600796510992165}
2200196380433402720412708602545669147197224570567046828378058426583290367289568783280147399643216889661967638391658473045558227023134602849600796510992165
30a4ab92b3cf09e0980f7162a2cef5152c9caf84046bc19599f3968ad42f043f9811f4f9df35564903e040fd0dacecaf72e2ce68fd927aa05230e5bb24d53725
```

**hash of Public Key in HEX:**
6dc5d7c55790988004373b35b124eb2745c49cd4865318a9fe6c4db5e1990c15

**First 20 Bytes in HEX**
`6dc5d7c55790988004373b35b124eb2745c49cd4`

**DID in Base58 Encoding and without Encoding**
```
did:tys:2XhdfxCGMpz7MHEKBwbadCZd6aBd
did:tys:6dc5d7c55790988004373b35b124eb2745c49cd4
```


#### TYS DIDs

In TYS, any of the clients can submit a verifiable claim. All TYS member Organizations will be issued Root Certificates to join the business network. Organizations can generate credentials to operate nodes or admit their users to exercise the application. TYS Node Operators can run as many nodes as they desire with approval from the TYS Governance Body. Nodes could be endorser nodes or *commiter* nodes.

Suppliers are the holders of the credentials and buyers are considered as the relying parties. Any client with the role of an issuer can issue claims, but only a verifier can create a TYS DID after verifying the claim. In TYS a issuer can also play the role of a verifier. The following is an example of a TYS DID:

##### TYS DID Example
```
did:tys:2XhdfxCGMpz7MHEKBwbadCZd6aBd
```

##### TYS DID Document (Organization)
In TYS, a DID can be issued to a Business Entity such as a “Supplier” or to a verifiable claim.  A Business Entity DID will point to a collection of DIDs that represent verifiable Claims.  The Public Key of the Supplier can be used to securely request details of the verifiable claim such as document metadata and uploaded documents.
The following is an example of DID associated with a “Business Entity”.

###### Example 1
```
************************
Invoking Create Method
************************
DID Document:
{
  "@context": "https://w3id.org/did/v1",
  "id": "did:tys:DaW1iKJEMmyvjpyHJi9pw6rcCeq",
  "name": "Alice Corp",
  "owner": {
    "id": "did:tys:DaW1iKJEMmyvjpyHJi9pw6rcCeq",
    "type": "id"
  },
  "dc:created": {
    "dc:created": "",
    "id": "did:tys:DaW1iKJEMmyvjpyHJi9pw6rcCeq",
    "type": "xsd:dateTime"
  },
  "publicKey": [
    {
      "id": "did:tys:DaW1iKJEMmyvjpyHJi9pw6rcCeq#key1",
      "sec": "93f02d9a495018403fd5dd43d96a880c7b6ebc221f176f9456f0df95fa6b6a3360d4e4c22e66f29cb67f234e7d783013873155211b4b2f16276d5f180a8d8",
      "type": "ECDSA"
    }
  ],
  "authentication": "did:tys:DaW1iKJEMmyvjpyHJi9pw6rcCeq#key1",
  "sec:revoked": {
    "id": "did:tys:DaW1iKJEMmyvjpyHJi9pw6rcCeq",
    "sec": "",
    "type": "xsd:dateTime"
  },
  "type": "SUPPLIER"
}
```

###### Example 2
```
{
    “@context”: https://w3id.org/did/v1,
    "id": "did:tys:2XhdfxCGMpz7MHEKBwbadCZd6aBd",
    "publicKey": [{
        "id": " did:tys:2XhdfxCGMpz7MHEKBwbadCZd6aBd#keys-1",
        "type": ["ECDSA", "secp256r1"],
        “controller”: "did:tys:2XhdfxCGMpz7MHEKBwbadCZd6aBd",
        "publicKeyHex":
               "30a4ab92b3cf09e0980f7162a2cef5152c9caf84046bc19599f3968ad42f043f9811f4f9df35564903e040fd0dacecaf72e2ce68fd927aa05230e5bb24d53725"
    }],
    "authentication": [{
        // This key is referenced and described above
        "type": ["ECDSA", "secp256r1"],
        "publicKey": " did:tys:2XhdfxCGMpz7MHEKBwbadCZd6aBd#keys-1"
    }],
    "credentials": [{
        "type": "credential",
        "id": "did:tys:2BfdfxCGMpz7MHEKBwbadCZd6aBd#claim"
    },
    {
        "type": "credential",
        "id": "did:tys:3ZydfxCGMpz7MHEKBwbadCZd6aBd#claim"
    }],

}
```

#### TYS DID Document (Claim)
The following DID document represents a verifiable claim. The attributes of this type of document include
a.	Credential  Owner
b.	Credential Expiration Date
c.	Credential Issuance Date
d.	Credential Subject
e.	Credential Issuer
f.	Credential Pubic Key
g.	Signature of Verifier
h.	Service Endpoints
i.	Credential Type

**DID Document:**

```
  {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/did/v1"
    ],
    "owner": {
      "id": " did:tys:2XhdfxCGMpz7MHEKBwbadCZd6aBd",
      "type": "id"
    },
    "verifiableCredential": {
      "cred:expirationDate": {
        "expirationDate": "31/01/2020",
        "type": "xsd:dateTime"
      },
      "cred:issuanceDate": {
        "issuanceDate": "01/02/2019",
        "type": "xsd:dateTime"
      },
      "credentialSubject": "Insurance Certificate of USD 1 Million",
      "id": "did:tys:39ryrZi9nuaRCyBxPKZiCMi3Yzge",
      "issuer": {
        "cred:issuer": "AIA General Insurance",
        "id": "did:tys:12345678"
      },
      "publicKey": [
        {
          "id": "did:tys:39ryrZi9nuaRCyBxPKZiCMi3Yzge#key1",
          "sec": "59821f30bd123879b32098e6fbdf9a020d0d836bd629e7ca82c4138275af15bdbd3cc9ce0731319ab22dad8c7516df6c76928d623f13344258b88e087f50f158",
          "type": "ECDSA"
        }
      ],
      "serviceEndpoint": {
        "serviceEndpoint": "https://www.tys.com/documents/insdoc.ecr"
      },
      "signature": {
        "sec:signingAlgorithm": "RsaSignature2018",
        "signatureValue": "4048574891045760770709703117946836604384822674299714246985631999965462522002985594532011646191982200179610655476059934788095400135508507503376790195335512"
      },
      "type": [
        "Credential",
        "InsuranceCredential"
      ]
    }
  }
```

#### DID Transaction Process Flow
// TODO


#### TYS Functions
##### Create and Register a DID
TYS Clients can create/register an entity in the TYS Network by submitting a Verifiable Claim as a transaction. The issuer and the subject of this claim are the same DID that is being registered.
Here is an example of such a claim:
```
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/did/v1"
  ],
  "owner": {
    "id": " did:tys:2XhdfxCGMpz7MHEKBwbadCZd6aBd",
    "type": "id"
  },
  "verifiableCredential": {
    "cred:expirationDate": {
      "expirationDate": "31/01/2020",
      "type": "xsd:dateTime"
    },
    "cred:issuanceDate": {
      "issuanceDate": "01/02/2019",
      "type": "xsd:dateTime"
    },
    "credentialSubject": "Insurance Certificate of USD 1 Million",
    "id": "did:tys:39ryrZi9nuaRCyBxPKZiCMi3Yzge",
    "issuer": {
      "cred:issuer": "AIA General Insurance",
      "id": "did:tys:12345678"
    },
    "publicKey": [
      {
        "id": "did:tys:39ryrZi9nuaRCyBxPKZiCMi3Yzge#key1",
        "sec": "59821f30bd123879b32098e6fbdf9a020d0d836bd629e7ca82c4138275af15bdbd3cc9ce0731319ab22dad8c7516df6c76928d623f13344258b88e087f50f158",
        "type": "ECDSA"
      }
    ],
    "serviceEndpoint": {
      "serviceEndpoint": "https://www.tys.com/documents/insdoc.ecr"
    },
    "signature": {
      "sec:signingAlgorithm": "RsaSignature2018",
      "signatureValue": "4048574891045760770709703117946836604384822674299714246985631999965462522002985594532011646191982200179610655476059934788095400135508507503376790195335512"
    },
    "type": [
      "Credential",
      "InsuranceCredential"
    ]
  }
}
```

The [DID Document](https://w3c-ccg.github.io/did-spec/#did-documents) representing the entity is included in the body of the claim.
This transaction is approved and the entity is registered if all of these conditions are true:
1.	if the did in the issuer, claim.id and claim.document.id fields match
2.	if the *claim.document.publicKey* contains at least one public key that when run through the process described in the section on [Generating a unique idstring](https://github.com/ockam-network/did-method-spec/blob/master/README.md#generating-a-unique-idstring) results in the exact DID from the *issuer*, *claim.id* and *claim.document.idfields*.
3.	if the signature on the claim is by one of the public keys mentioned in the DID document as approved for auth.

##### Read
TYS Clients can read a DID document by sending a query request for a DID.
For example a query for `did:tys:2Mm9pLRQwueo7FJUvBoDW7QKGBXTX` would return:
```
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/did/v1"
  ],
  "owner": {
    "id": " did:tys:2XhdfxCGMpz7MHEKBwbadCZd6aBd",
    "type": "id"
  },
  "verifiableCredential": {
    "cred:expirationDate": {
      "expirationDate": "31/01/2020",
      "type": "xsd:dateTime"
    },
    "cred:issuanceDate": {
      "issuanceDate": "01/02/2019",
      "type": "xsd:dateTime"
    },
    "credentialSubject": "Insurance Certificate of USD 1 Million",
    "id": "did:tys:39ryrZi9nuaRCyBxPKZiCMi3Yzge",
    "issuer": {
      "cred:issuer": "AIA General Insurance",
      "id": "did:tys:12345678"
    },
    "publicKey": [
      {
        "id": "did:tys:39ryrZi9nuaRCyBxPKZiCMi3Yzge#key1",
        "sec": "59821f30bd123879b32098e6fbdf9a020d0d836bd629e7ca82c4138275af15bdbd3cc9ce0731319ab22dad8c7516df6c76928d623f13344258b88e087f50f158",
        "type": "ECDSA"
      }
    ],
    "serviceEndpoint": {
      "serviceEndpoint": "https://www.tys.com/documents/insdoc.ecr"
    },
    "signature": {
      "sec:signingAlgorithm": "RsaSignature2018",
      "signatureValue": "4048574891045760770709703117946836604384822674299714246985631999965462522002985594532011646191982200179610655476059934788095400135508507503376790195335512"
    },
    "type": [
      "Credential",
      "InsuranceCredential"
    ]
  }
}
```

##### Update:
TYS Clients can update a DID document by submitting a [Verifiable Claim](https://www.w3.org/TR/verifiable-claims-data-model/) as a transaction. The **issuer** and the **subject** of this claim are the same DID that is being updated.

```
{
  "@context": "https://w3id.org/did/v1",
  "UpdateDidDescription": {
    "UpdateDidDescription": "old_value=xxxx:new_value=yyyy"
  },
  "authentication": "did:tys:DaW1iKJEMmyvjpyHJi9pw6rcCeq#key1",
  "id": "did:tys:DaW1iKJEMmyvjpyHJi9pw6rcCeq",
  "name": "Alice Corp",
  "nonce": "1",
  "publicKey": [
    {
      "id": "did:tys:DaW1iKJEMmyvjpyHJi9pw6rcCeq#key1",
      "sec": "93f02d9a495018403fd5dd43d96a880c7b6ebc221f176f9456f0df95fa6b6a3360d4e4c22e66f29cb67f234e7d783013873155211b4b2f16276d5f180a8d8",
      "type": "ECDSA"
    }
  ],
  "type": "SUPPLIER"
}
```

This transaction is approved, and the entity is updated if all these conditions are true:
1.	if the did in the issuer, claim.id and claim.document.id fields match.
2.	if the signature on the claim is by one of the public keys mentioned in the DID document as approved for authentication.

##### Deactivate
Tys Clients can revoke a DID document by submitting a [Verifiable Claim](https://www.w3.org/TR/verifiable-claims-data-model/) as a transaction. The **issuer**  and the **subject** of this claim are the same DID that is being revoked.

The document field is set to *null*.

```
{
  "@context": "https://w3id.org/did/v1",
  "UpdateDidDescription": {
    "UpdateDidDescription": "revoked"
  },
  "id": "did:tys:DaW1iKJEMmyvjpyHJi9pw6rcCeq",
  "name": "Alice Corp",
  "nonce": "1",
  "publicKey": [
    {
      "id": "did:tys:DaW1iKJEMmyvjpyHJi9pw6rcCeq#key1",
      "sec": "",
      "type": "ECDSA"
    }
  ],
  "sec:revoked": {
    "id": "did:tys:DaW1iKJEMmyvjpyHJi9pw6rcCeq",
    "sec": "18/04/2019",
    "type": "xsd:dateTime"
  },
  "type": "SUPPLIER"
}
```

This transaction is approved and the entity is deactivated if all these conditions are true:

1.	if the did in the issuer and claim.id fields match.
2.	if the signature on the claim is by one of the public keys mentioned in the DID document as approved for authentication.



##### GetAllCredentialsForEntity
This service queries retrieves all dids associated with the holder. It is typically based on access privileges. The access privileges are provided to buyer, auditor and regulator.

```
{
    “@context”: https://w3id.org/did/v1,
    "id": "did:tys:2XhdfxCGMpz7MHEKBwbadCZd6aBd",
    "publicKey": [{
        "id": " did:tys:2XhdfxCGMpz7MHEKBwbadCZd6aBd#keys-1",
        "type": ["ECDSA", "secp256r1"],
        “controller”: "did:tys:2XhdfxCGMpz7MHEKBwbadCZd6aBd",
        "publicKeyHex":
               "30a4ab92b3cf09e0980f7162a2cef5152c9caf84046bc19599f3968ad42f043f9811f4f9df35564903e040fd0dacecaf72e2ce68fd927aa05230e5bb24d53725"
    }],
    "authentication": [{
        // This key is referenced and described above
        "type": ["ECDSA", "secp256r1"],
        "publicKey": " did:tys:2XhdfxCGMpz7MHEKBwbadCZd6aBd#keys-1"
    }],
    "credentials": [{
        "type": "credential",
        "id": "did:tys:2BfdfxCGMpz7MHEKBwbadCZd6aBd#claim"
    },
    {
        "type": "credential",
        "id": "did:tys:3ZydfxCGMpz7MHEKBwbadCZd6aBd#claim"
    }],

}
```

#### Status

This document is a work in progress draft.

#### References
1.	TYS URL http://www.trustyoursupplier.com
2.	Decentralized Identifiers (DIDs) v0.11 https://w3c-ccg.github.io/did-spec
3.	ABNF https://tools.ietf.org/html/rfc5234
4.	Multihash - Self-describing hashes https://multiformats.io/multihash/
5.	The Multihash Data Format https://tools.ietf.org/html/draft-multiformats-multihash-00
6.	Multihash Labels https://github.com/multiformats/multicodec/blob/master/table.csv
7.	Base58 Encoding https://en.wikipedia.org/wiki/Base58
8.	Bitcoin Base58 Alphabet https://en.bitcoinwiki.org/wiki/Base58#Alphabet_Base58
9.	Linked Data Cryptographic Suite Registry https://w3c-ccg.github.io/ld-cryptosuite-registry
10.	Verifiable Claims https://www.w3.org/TR/verifiable-claims-data-model
11.	JSON-LD 1.0 - A JSON-based Serialization for Linked Data https://www.w3.org/TR/json-ld
