
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


```log
# git clone https://github.com/salrashid123/golang-jwt-tpm.git
# cd util
# go run keycreate.go 

2022/10/02 13:26:33 0 handles flushed
2022/10/02 13:26:33      key Name: 
dcbf8bc4563cca44c96f795e29806c3c6e1529cdecc16899fad5862fd358ae50
2022/10/02 13:26:33 ======= ContextSave (k) ========
2022/10/02 13:26:33      PublicKey: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyrQsZpVRuStYgpyoK1i8
rcYyaR5nCdS877Zji/bUqBEPxxVBoB21M/amr3pSKRRiHWBO0LYqonFEJAgDkuw2
JmlgiN30LVElc7KnLZ1dwVnClYO7VF5QW9jDBZfAPEzsjt2S6k+n6w7KjqZfmnUj
hM1OabYv9BKs6pRswS8AN0ldLc8yd6aYHLZBWX5i6JC0b8WhauNz9+O+x20vbufD
iGfpocccoQc717NxtXDksIK2dsv2CPPGevZ8Z8+pMngODKWahlAVoBYBaunF9dQr
DFdy+1r7HaZyyqu1/WIh3k/Fxe6PGPllqvA4n4+rHPJFekkBBTR2HOES+yoXiO8M
MwIDAQAB
-----END PUBLIC KEY-----
2022/10/02 13:26:33 Public Key written to: key.pem
JWK Format:
{
  "e": "AQAB",
  "kid": "+0gg+AON1Ig4VoxZXEKMjEi/m0B5NoyX+SkaZdAYZuE",
  "kty": "RSA",
  "n": "yrQsZpVRuStYgpyoK1i8rcYyaR5nCdS877Zji_bUqBEPxxVBoB21M_amr3pSKRRiHWBO0LYqonFEJAgDkuw2JmlgiN30LVElc7KnLZ1dwVnClYO7VF5QW9jDBZfAPEzsjt2S6k-n6w7KjqZfmnUjhM1OabYv9BKs6pRswS8AN0ldLc8yd6aYHLZBWX5i6JC0b8WhauNz9-O-x20vbufDiGfpocccoQc717NxtXDksIK2dsv2CPPGevZ8Z8-pMngODKWahlAVoBYBaunF9dQrDFdy-1r7HaZyyqu1_WIh3k_Fxe6PGPllqvA4n4-rHPJFekkBBTR2HOES-yoXiO8MMw"
}
```

The output of the create command is `key.bin` which is a TPM public key reference to the embedded key.  The output also includes `key.pem` (the public `RSA`)

Note that the output shows the PublicKey in RSA and JWK formats

Now create a test JWT and verify it with an RSA key that is extracted from a TPM and also directly. 

```log
# cd examples/
# go run main.go 

TOKEN: eyJhbGciOiJSUzI1NiIsImtpZCI6IiswZ2crQU9OMUlnNFZveFpYRUtNakVpL20wQjVOb3lYK1NrYVpkQVladUUiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2NjQ3MTczMTEsImlzcyI6InRlc3QifQ.M_9Xh8-ULkuu6TVAGd8UAIQI-K7DRBDp3GEANfa512nzMNZop7NIXLYdozy_k37FNu74s40CU4wX7l6zhjLiF84CCo98rw6TdtOewjsq8_FEFFalA4rLHB3nzbaRkmLq1J9n9eHZ1ueDSsONhCJ-MC_G8lPNSSMqcacxQX4GuU5IEawbZBiSPx2Gq-6_mstDjaJACNabOz13Kgp687XnZW5TBdSytRB0Gd1eZD0qALmZkoFtKMlmJ9qXOAIVZceAlg_hGeAXwSTTVfMZUgO-lknSPXVr0MYpWDpnefPtcmLdbYtWyjP73uzU6JHIwP8EszrPGlK3Um3SZgQBdummLQ
2022/10/02 13:27:31      verified with TPM PublicKey
2022/10/02 13:27:31      verified with exported PubicKey

```

The JWT is formatted as:


```json
{
  "alg": "RS256",
  "kid": "+0gg+AON1Ig4VoxZXEKMjEi/m0B5NoyX+SkaZdAYZuE",
  "typ": "JWT"
}
{
  "exp": 1638131530,
  "iss": "test"
}
```

Where the `keyID` is the base64 encoded hash of the DER public key

```bash
$ openssl rsa -pubin -in util/key.pem -outform DER | openssl sha256
writing RSA key
SHA256(stdin)= fb4820f8038dd48838568c595c428c8c48bf9b4079368c97f9291a65d01866e1

# base64 of hex fb4820f8038dd48838568c595c428c8c48bf9b4079368c97f9291a65d01866e1 --> +0gg+AON1Ig4VoxZXEKMjEi/m0B5NoyX+SkaZdAYZuE=
```

to use, just import the library configure the TPM.  Remember to set the override so that the correct `alg` is defined in the JWT header

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

	// set override
	tpmjwt.SigningMethodTPMRS256.Override()

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