
# golang-jwt for Trusted Platform Module (TPM)

This is just an extension for [go-jwt](https://github.com/golang-jwt/jwt#extensions) i worte over thanksgiving that allows creating and verifying JWT tokens where the private key is embedded inside a [Trusted platform module](https://en.wikipedia.org/wiki/Trusted_Platform_Module).

You can use this library to sign and verify a JWT using the standard `go-jwt` library semantics.

This library also includes a utility function to create an RSA key inside a TPM and also print its public key in `RSA` and `JWK` formats.

Using a TPM to sign or encrypt anything has some very specific applications which i will not go into it much (if your'e reading this, you probably already know).  If a JWT is signed by a TPM and if the key that was used was setup in a specific format, the verifier can be sure that the JWT was signed by that TPM _only_.

For example, you can use a TPM to generate an RSA key with specifications that "this key was generated on a TPM with characteristics that it is not exportable outside the TPM"..very necessarily, the RSA private key will never exist anywhere else other than in that TPM.

How a you trust that a specific RSA key happens to be from a given TPM is a rather complicated protocol that is also not covered in this repo.  The specifc trust protocol is called [TPM Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html).

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

To use this library, you need a TPM to issue a JWT. You do not need a TPM to verify; you just need the public key.  On linux, its usally at `/dev/tpm0`

The sample setup uses a [GCP Shielded VM](https://cloud.google.com/security/shielded-cloud/shielded-vm).  You can use any system that has a TPM (including a raspberryPi)

Setup 

```bash
gcloud compute  instances create   tpm-device     \
   --zone=us-central1-a --machine-type=n1-standard-1 \
   --tags tpm       --no-service-account  --no-scopes  \
   --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
   --image=debian-10-buster-v20210916 --image-project=debian-cloud

# ssh to VM

## this library uses go-tpm-tools which...unfortunatley requires the folloing ONLY on the system
## that generates the JWT;  any verifier just needs the public key
##  https://github.com/google/go-tpm-tools#trousers-errors-when-building-server
apt-get update && apt-get install gcc libtspi-dev
```

Once on the VM, create a key on TPM (if you already have an existing key on TPM, you can acquire a handle using `go-tpm-tools`).  For now, create a key


```log
# git clone https://github.com/salrashid123/golang-jwt-tpm.git
# cd util
# go run keycreate.go 

2021/11/28 20:30:03 ======= Init  ========
2021/11/28 20:30:03 0 handles flushed
2021/11/28 20:30:03      key Name: 
5e41119a2fe12b8fcff3ad663d8aaa96d840ce765d92a256c503bf63060fc5d6
2021/11/28 20:30:03 ======= ContextSave (k) ========
2021/11/28 20:30:03      PublicKey: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyhUost8vRhTv/O3lsLQN
za3CdkBVntiZcny7jh2GXi16CtV8Y8bbmWlmACih+0f5SourEbTHiz1zr9AJ6VmQ
EuOVBv0WBXqUpeUVAUGDrJVJt3qwnTyLUgZmyE158J3HpuI9qV2Q4Z7mkUSGaapk
kWGvWd66Me2CqjKDVtJvVxdZhM6PkdrfAUuTdnmfOQ0637YxVzg6S9Jb/Tbmye17
ZsT+sbGx0Atn86r9anVWeXrraXYJ3t42ArYp0UV87hB/p1RU2yofUSu+afeX8tEU
PNAYZQZaCRCnkIjfFtyEpobsU0/9QZ9htPAfToca3YdTZ9W/QOUpYZrWIxWRxvM0
ZQIDAQAB
-----END PUBLIC KEY-----
2021/11/28 20:30:03 Public Key written to: key.pem
JWK Format:
{
  "e": "AQAB",
  "kid": "5e41119a2fe12b8fcff3ad663d8aaa96d840ce765d92a256c503bf63060fc5d6",
  "kty": "RSA",
  "n": "yhUost8vRhTv_O3lsLQNza3CdkBVntiZcny7jh2GXi16CtV8Y8bbmWlmACih-0f5SourEbTHiz1zr9AJ6VmQEuOVBv0WBXqUpeUVAUGDrJVJt3qwnTyLUgZmyE158J3HpuI9qV2Q4Z7mkUSGaapkkWGvWd66Me2CqjKDVtJvVxdZhM6PkdrfAUuTdnmfOQ0637YxVzg6S9Jb_Tbmye17ZsT-sbGx0Atn86r9anVWeXrraXYJ3t42ArYp0UV87hB_p1RU2yofUSu-afeX8tEUPNAYZQZaCRCnkIjfFtyEpobsU0_9QZ9htPAfToca3YdTZ9W_QOUpYZrWIxWRxvM0ZQ"
}
```

The output of the create command is `key.bin` which is a TPM public key reference to the embedded key.  The output also includes `key.pem` (the public `RSA`)

Note that the output shows the PublicKey in RSA and JWK formats

Copy the file `key.bin` into the `examples/` folder

Now create a test JWT and verify it with an RSA key that is extracted from a TPM and also directly. 

```log
# cd examples/
# go run main.go 
TOKEN: eyJhbGciOiJSUzI1NiIsImtpZCI6IjVlNDExMTlhMmZlMTJiOGZjZmYzYWQ2NjNkOGFhYTk2ZDg0MGNlNzY1ZDkyYTI1NmM1MDNiZjYzMDYwZmM1ZDYiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2MzgxMzE1MzAsImlzcyI6InRlc3QifQ.R1CZ1XqXyrMHk77m1Ehj6r4c1pQVFqTRrJ-ij-Y3HFMY5n07orlWGffuiXQU-nXv9coqoncaj3T7a2inF0Qwow5GSPoBdueYVt7bGdU9p7Tb5fC-6OLMwm8JjqrCtFKAjjyLuBGiaLkZ6aZFCouzyQljL_TWx8Lz7_0wZewpX4SUlXNq3aa9pnP5AfmACfrj3_Ds4UllghGO2xHgNxFeAdlr3gvYOZmLIrLwT5KnAV4ZEu-tRJy6ej8qHHNUiNZZ1UkyY_U6SLDmzW8Cu9JbtXLF0b9kbU98bcGZr41bAdRbKxqclTNi04k7ZC2iVS6H0jFTHYwefLBdjXS9yDDLtA
2021/11/28 20:31:10      verified with TPM PublicKey
2021/11/28 20:31:10      verified with exported PubicKey
```

The JWT is formatted as:

```json
{
  "alg": "RS256",
  "kid": "5e41119a2fe12b8fcff3ad663d8aaa96d840ce765d92a256c503bf63060fc5d6",
  "typ": "JWT"
}
{
  "exp": 1638131530,
  "iss": "test"
}
```

to use, just import the library configure the TPM:

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

	tpmjwt.SigningMethodTPMRS256.Override() // RS256

	ctx := context.Background()

	var keyctx interface{}
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

	config := &tpmjwt.TPMConfig{
		TPMDevice:     "/dev/tpm0",
		KeyHandleFile: "key.bin",
		KeyTemplate:   tpmjwt.AttestationKeyParametersRSA256,
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