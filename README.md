
# golang-jwt for Trusted Platform Module (TPM)

This is just an extension for [go-jwt](https://github.com/golang-jwt/jwt#extensions) i wrote over thanksgiving that allows creating and verifying JWT tokens where the private key is embedded inside a [Trusted platform module](https://en.wikipedia.org/wiki/Trusted_Platform_Module).

You can use this library to sign and verify a JWT using the standard `go-jwt` library semantics.

This library also includes a utility function to create an RSA key inside a TPM and also print its public key in `RSA` and `JWK` formats.

Using a TPM to sign or encrypt anything has some very specific applications which i will not go into it much (if your'e reading this, you probably already know).  If a JWT is signed by a TPM and if the key that was used was setup in a specific format, the verifier can be sure that the JWT was signed by that TPM _only_.

For example, you can use a TPM to generate an RSA key with specifications that "this key was generated on a TPM with characteristics such that it cannot get exportable outside the TPM"..very necessarily, the RSA private key will never exist anywhere else other than in that TPM.

How a you trust that a specific RSA key happens to be from a given TPM with a given specification set is a rather complicated protocol that is also not covered in this repo.  The specific trust protocol is called [TPM Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html).

This repo assumes the verifier of the JWT has already established that the RSA key that is being used to sign the JWT

>> this repo is not supported by google

Other references

* [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)
* [TPM Remote Attestation protocol using go-tpm and gRPC](https://github.com/salrashid123/go_tpm_remote_attestation)
* [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)
* [Attribute Certificates](https://github.com/salrashid123/attribute_certificate)
* [Google Cloud IoT Core Authentication with Trusted Platform Module (TPM)](https://github.com/salrashid123/iot_tpm_auth)


Much of this implementation is inspired templated form [gcp-jwt-go](https://github.com/someone1/gcp-jwt-go)

### Supported Key Types

The following types are supported

* `RSA+SHA256`

### Setup

To use this library, you need a TPM to issue a JWT. You do not need a TPM to verify; you just need the public key.  On linux, its usually at `/dev/tpm0`

The sample setup uses a [GCP Shielded VM](https://cloud.google.com/security/shielded-cloud/shielded-vm).  You can use any system that has a TPM (including a raspberryPi with a fancy extra on chip)

Setup 

```bash
gcloud compute  instances create   tpm-device     \
   --zone=us-central1-a --machine-type=n1-standard-1 \
   --tags tpm       --no-service-account  --no-scopes  \
   --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
   --image=debian-10-buster-v20210916 --image-project=debian-cloud

# ssh to VM

## this library uses go-tpm-tools which...unfortunately requires the following ONLY on the system
## that generates the JWT;  any verifier just needs the public key
##  https://github.com/google/go-tpm-tools#trousers-errors-when-building-server
apt-get update && apt-get install gcc libtspi-dev
```

Once on the VM, create a key on TPM (if you already have an existing key on TPM, you can acquire a handle using `go-tpm-tools`).  For now, create a key

The key created is _persisted_ at a handle (default `0x81008000`) and you can pick any defined in pg 15 of [Registry of Reserved TPM 2.0 Handles and Localities](https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf)


basically in base 16: `81000000 --> 817FFFFF`

```log
# git clone https://github.com/salrashid123/golang-jwt-tpm.git
# cd util

# go run keycreate.go  --persistentHandle 0x81008000

2023/08/25 10:33:20 ======= Init  ========
2023/08/25 10:33:20      key Name: 
b96d36c1514a1e00f0213c5f52f5c74e5d439f5b333360330ef5695ec27d9100
2023/08/25 10:33:20 ======= PersistHandle (k) ========
2023/08/25 10:33:20      PublicKey: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvenLjnHCMRr9XEcYZ7rR
qMUF5jAdFXqumrKG+uVYLR/7VNJAF3XgQRrEF/SjTMIwYXgzk0w6JK+fVVPFjiRf
7Jnm4eEvd3uBXHTs3JSosQ8E6DvArSJ7RyXslj7B/l1Fth/a2CUuMngY+KD7e+bL
iLnZj7P16MVaUQtwHIlcE5wctW0o1ZomOUqMyffn1pCKtgQ3Sgh/d2/LHH+xIzbH
fNzqXLVVvZ0yuIq8efuCcvEDj5ad5r7eJ330lVkLF12p9gzYVDzhVTpvr2GCHiab
GhqVxDAS6lUb+H6IvayqlyCw/HLyqJ0+uldz0FHTusUsYkFJB5a7HF3vTG+vzhzq
/wIDAQAB
-----END PUBLIC KEY-----
2023/08/25 10:33:20 Public Key written to: key.pem
JWK Format:
{
  "e": "AQAB",
  "kid": "OalzExXmgY8n+ot1Fuq3W3RdaMfXwvz6L/rcZMVrQfU",
  "kty": "RSA",
  "n": "venLjnHCMRr9XEcYZ7rRqMUF5jAdFXqumrKG-uVYLR_7VNJAF3XgQRrEF_SjTMIwYXgzk0w6JK-fVVPFjiRf7Jnm4eEvd3uBXHTs3JSosQ8E6DvArSJ7RyXslj7B_l1Fth_a2CUuMngY-KD7e-bLiLnZj7P16MVaUQtwHIlcE5wctW0o1ZomOUqMyffn1pCKtgQ3Sgh_d2_LHH-xIzbHfNzqXLVVvZ0yuIq8efuCcvEDj5ad5r7eJ330lVkLF12p9gzYVDzhVTpvr2GCHiabGhqVxDAS6lUb-H6IvayqlyCw_HLyqJ0-uldz0FHTusUsYkFJB5a7HF3vTG-vzhzq_w"
}
```

Note, if the handle is already defined, you can evict it with `-evict` flag (equivalent of `tpm2_evictcontrol -C o -c  0x81008000`)

The output of the create command make a perisstent key at the value of `persistentHandle`.  The output also includes `key.pem` (the public `RSA`)

Note that the output shows the PublicKey in RSA and JWK formats

Now create a test JWT and verify it with an RSA key that is extracted from a TPM and also directly. 

```log
# cd examples/
# go run main.go --persistentHandle 0x81008000

TOKEN: eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9hbHpFeFhtZ1k4bitvdDFGdXEzVzNSZGFNZlh3dno2TC9yY1pNVnJRZlUiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2OTI5NTk3NTgsImlzcyI6InRlc3QifQ.l1n5luU4UoHiRcDdIMUSFkJvozKOxm2D3ze8___Jo0oI4XSjDT1gNr-01KYA5GzQBr_d34hwypo_Pzol9Brcne2OFliQCtzxqzolBvhK_HcHzjtZBTCMJ87mLefDOgoIU_PW9nDnfxMnchDKbQLkdO9U6e8qJLzNYLP0pkPnPxrh2qjywt_I5SFCTLuUSMLIIAzM31eQuizysr7riwMLHbX8jIuS_2aZ9Nn7YxDtFJzfWLYhoa7MLu-DAdu5XjqyJ1oVXhM8Au1NyRpy7WIlKHVuzqxyEDi5pwKqTehUgWBmX_5eUUysNNmaXkWdbrIMSv9Eq3-9X4i6gWTB4VRuDQ
2023/08/25 10:34:58      verified with TPM PublicKey
2023/08/25 10:34:58      verified with exported PubicKey


```

The JWT is formatted as:


```json
{
  "alg": "RS256",
  "kid": "OalzExXmgY8n+ot1Fuq3W3RdaMfXwvz6L/rcZMVrQfU",
  "typ": "JWT"
}
{
  "exp": 1692959758,
  "iss": "test"
}
```

Where the `keyID` is the base64 encoded hash of the DER public key

```bash
$ openssl rsa -pubin -in util/key.pem -outform DER | openssl sha256
writing RSA key
SHA256(stdin)= 39a9731315e6818f27fa8b7516eab75b745d68c7d7c2fcfa2ffadc64c56b41f5

# base64 of hex 39a9731315e6818f27fa8b7516eab75b745d68c7d7c2fcfa2ffadc64c56b41f5 --> OalzExXmgY8n+ot1Fuq3W3RdaMfXwvz6L/rcZMVrQfU=
```

to use, just import the library configure the TPM.  Remember to set the override so that the correct `alg` is defined in the JWT .


You must have a key already defined and persisted to NV (transient keys not supported)

```golang
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
)

var ()

func main() {

	ctx := context.Background()

	var keyctx interface{}
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		Issuer:    "test",
	}

	tpmjwt.SigningMethodTPMRS256.Override()
	token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

	config := &tpmjwt.TPMConfig{
		TPMDevice:   "/dev/tpm0",
		KeyHandle:   0x81008000,
		KeyTemplate: tpmjwt.AttestationKeyParametersRSA256,
		//KeyTemplate: tpmjwt.UnrestrictedKeyParametersRSA256,
	}

	keyctx, err := tpmjwt.NewTPMContext(ctx, config)
	if err != nil {
		log.Fatalf("Unable to initialize tpmJWT: %v", err)
	}

	token.Header["kid"] = config.GetKeyID()
	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		log.Fatalf("Error signing %v", err)
	}
	fmt.Printf("TOKEN: %s\n", tokenString)

	// verify with TPM based publicKey
	keyFunc, err := tpmjwt.TPMVerfiyKeyfunc(ctx, config)
	if err != nil {
		log.Fatalf("could not get keyFunc: %v", err)
	}

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if vtoken.Valid {
		log.Println("     verified with TPM PublicKey")
	}

	// verify with provided RSAPublic key
	pubKey := config.GetPublicKey()

	v, err := jwt.Parse(vtoken.Raw, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if v.Valid {
		log.Println("     verified with exported PubicKey")
	}

}

```