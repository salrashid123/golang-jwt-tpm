# golang-jwt for Trusted Platform Module (TPM)

This is just an extension for [go-jwt](https://github.com/golang-jwt/jwt#extensions) i wrote over thanksgiving that allows creating and verifying JWT tokens where the private key is embedded inside a [Trusted platform module](https://en.wikipedia.org/wiki/Trusted_Platform_Module).

You can use this library to sign and verify a JWT using the standard `go-jwt` library semantics.

This library also includes a utility function to create an RSA key inside a TPM and also print its public key in `RSA` and `JWK` formats.

Using a TPM to sign or encrypt anything has some very specific applications which i will not go into it much (if your'e reading this, you probably already know).  If a JWT is signed by a TPM and if the key that was used was setup in a specific format, the verifier can be sure that the JWT was signed by that TPM.

For example, you can use a TPM to generate an RSA key with specifications that "this key was generated on a TPM with characteristics such that it cannot get exportable outside the TPM"..very necessarily, the RSA private key will never exist anywhere else other than in that TPM.

How a you trust that a specific RSA or ECC key happens to be from a given TPM with a given specification set is a rather complicated protocol that is also not covered in this repo.  The specific trust protocol is called [TPM Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html).

This repo assumes the verifier of the JWT has already established that the RSA key that is being used to sign the JWT

>> this repo is not supported by google

### Supported Key Types

The following types are supported

* `RS256`
* `ES256`

against the TPM `OWNER` hierarchy

### Usage

Use this library to issue JWTs in a way compatible with golang-jwt library.  The difference is that the caller must initialize a `client.Key` object from [go-tpm-tools](https://github.com/google/go-tpm-tools):

```golang
import (
	"github.com/golang-jwt/jwt/v5"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// initialize the TPM
rwc, err := tpm2.OpenTPM(*tpmPath)
defer rwc.Close()

// get a client.Key object which references the embedded RSA key
var k *client.Key
k, err = client.LoadCachedKey(rwc, tpmutil.Handle(*persistentHandle), nil)
//k, err = client.LoadCachedKey(rwc, tpmutil.Handle(*persistentHandle), client.EKSession{})

// pass those to this library
config := &tpmjwt.TPMConfig{
	TPMDevice: rwc,
	Key:       k,
}

keyctx, err := tpmjwt.NewTPMContext(ctx, config)

claims := &jwt.RegisteredClaims{
	ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
	Issuer:    "test",
}

tpmjwt.SigningMethodTPMRS256.Override()
token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)
tokenString, err := token.SignedString(keyctx)
fmt.Printf("TOKEN: %s\n", tokenString)
```

### Setup

To use this library, you need a TPM to issue a JWT. You do not need a TPM to verify; you just need the public key.  On linux, its usually at `/dev/tpm0`

The sample setup uses a [GCP Shielded VM](https://cloud.google.com/security/shielded-cloud/shielded-vm).  You can use any system that has a TPM (including a raspberryPi with a fancy extra on chip)

Setup 

```bash
gcloud compute  instances create   tpm-device     \
   --zone=us-central1-a --machine-type=n1-standard-1 \
   --tags tpm       --no-service-account  --no-scopes  \
   --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
   --image-family=debian-11 --image-project=debian-cloud

# ssh to VM
apt-get update
apt-get install tpm2-tools
# wget https://go.dev/dl/go1.22.2.linux-amd64.tar.gz
#rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz
# export PATH=$PATH:/usr/local/go/bin
```

Once on the VM, create a key on TPM (if you already have an existing key on TPM, you can acquire a handle using `go-tpm-tools`).  For now, create a key

The key created is _persisted_ at a handle (default `0x81008001`) and you can pick any defined in pg 15 of [Registry of Reserved TPM 2.0 Handles and Localities](https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf)


### Usage


For simplicity, the following generates and embeds keys into a persistent handle using [tpm2_tools](https://github.com/tpm2-software/tpm2-tools)

#### RSA 

Create RSA key at handle `0x81008001`

```bash
# or with tpm2_tools
# tpm2_flushcontext -t -s -l
# tpm2_evictcontrol -C o -c 0x81008001
 tpm2_createprimary -C e -c primary.ctx
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008001
```

Then,

```bash
cd example/
go run nopolicy/main.go --persistentHandle=0x81008001

    2024/04/07 13:03:46 ======= Init  ========
    2024/04/07 13:03:46      Signing PEM 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2hhvvxAtjSeYi+M07nV
    weY/JqICYbJ4SsqvBdzguGrYVK9ITuZvHe8z0QG2d/+fCyEb+30rqgoy+0BugImV
    YdCEg6WZJ/j2Tvj0v1ItmCQoPgNWZ/oqY4U11eSqb1RAho/HWbkCDBZoP1BbdQ/T
    kdc+JKy94xETK+Mnq26Tr0tK9t4PwxPeXvweWwNB+kSBAWmDO9hJo+UKCysvPZ4K
    6SMOb8p4HmCjzAZ06VBgfrW/17rcdwKqS6ImDKhzAbkkC15Qdfx71YkZGnvLehi6
    8FGDF7IHbk846ki5Z91Jvnp5jjcqqQYajYwn7lNHNgMPDS2REoUTzbVHzSAcpVgl
    9QIDAQAB
    -----END PUBLIC KEY-----
    TOKEN: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTI0OTUwODYsImlzcyI6InRlc3QifQ.qVb3W2oS0GpgJgNpmsEP4PUKXzSGmihQadLCMYP04_qwlWnYFU7fU3KCTXZ9bpKs92ksRavIPOna_MCPrRj_VJBnEdjl1HGLw0B-_1BLz2JwuwGgOx2NCE-xmkYJJ7bLKiIV8nKbUvJq19GhoKaKzHl2f9Gy4dirKGSE3DztNUuWl3ValFtWyl69FpkJEAEWtQnnDhhQIJ1H3uu4iYJ1AY0L95C502oqD2BSaye0HImHolPN-UkCQ1iEOXMEYNnrllUTfPQ82p875ubvXCnilSasE0ozKOxPLyctkPlssojiM41kdj6-uqaoKvG84zEFGVZUIXk2bc7cFYhj8fR1Lw
    2024/04/07 13:03:46      verified with TPM PublicKey
    2024/04/07 13:03:46      verified with exported PubicKey
```

#### ECC 

```bash
 tpm2_createprimary -C e -c primary.ctx
 tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008002    
```

Then

```bash
cd example/
go run nopolicy/main.go --persistentHandle=0x81008002

    2024/04/07 13:04:59 ======= Init  ========
    2024/04/07 13:04:59      Signing PEM 
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYt1Dra/va/RSzH+eQKGDbtr+CE4U
    7P1wnRR6Hb/S45i/PxI3PdIuZoFzswvVt0sLvSmG1pvyawDHwD04UXT01A==
    -----END PUBLIC KEY-----
    TOKEN: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTI0OTUxNTksImlzcyI6InRlc3QifQ.cnFyy1ByWW2yFukw3yFbBVyq1nGy63FEx_2a3bL1Wh7EFqJ3z-5Lg7Eh1W-dtYZPVK_k-OExBSjpBIGwJ4aQJQ
    2024/04/07 13:04:59      verified with TPM PublicKey
    2024/04/07 13:04:59      verified with exported PubicKey

```

Notice the public key matches the one we saved to the handle

The JWT is formatted as:


```json
{
  "alg": "RS256",
  "typ": "JWT"
}
{
  "exp": 1711887476,
  "iss": "test"
}
```

```json
{
  "alg": "ES256",
  "typ": "JWT"
}
{
  "exp": 1711887484,
  "iss": "test"
}
```

You must have a key already defined and persisted to NV (transient keys not supported)

### Imported Key

If you want to [import an external RSA key to the TPM](https://github.com/salrashid123/tpm2/tree/master/tpm_import_external_rsa#importing-an-external-key), you will need to define a persistent handle as well.

using `tpm2_tools`:

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem

	tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
	tpm2_import -C primary.ctx -G rsa2048:rsassa:null -g sha256  -i private.pem -u key.pub -r key.prv
	tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008003

echo "my message" > message.dat
tpm2_sign -c key.ctx -g sha256 -o sig1.rssa message.dat
tpm2_verifysignature -c key.ctx -g sha256 -s sig1.rssa -m message.dat
tpm2_evictcontrol -C o -c key.ctx 0x81008003
```

You can also see how to load the entire chain here [Loading TPM key chains](https://github.com/salrashid123/tpm2/context_chain)


#### With Session and Policy

If a key is bound to a PCR policy, you can specify that inline during key initialization.

For example, the following has `PCR=23` policy bound:

```golang
	s, err := client.NewPCRSession(rwc, tpm2.PCRSelection{tpm2.AlgSHA256, []int{23}})
	defer s.Close()

	sessionKey, err := client.LoadCachedKey(rwc, tpmutil.Handle(*persistentHandle), s)
	defer sessionKey.Close()

	sessionConfig := &tpmjwt.TPMConfig{
		TPMDevice: rwc,
		Key:       sessionKey,
	}
```

Which you can initialize though:

```bash
## first print the value at pcr 23:
# tpm2_flushcontext -t -s -l
# tpm2_evictcontrol -C o -c 0x81008004
# tpm2_pcrread sha256:23
#   sha256:
#     23: 0x0000000000000000000000000000000000000000000000000000000000000000

## you can optionally 'extend' the value to get a new PCR to use (default for 23 if unset is usually all those 0's)
# tpm2_pcrextend  23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
# tpm2_pcrread sha256:23
#   sha256:
#     23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

## create an auth sesison and the two polcies 
tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
tpm2_flushcontext session.dat

## create the parent
tpm2_createprimary -C o -c primary2.ctx

tpm2_create -G rsa2048:rsassa:null -g sha256 -u rsa2.pub -r rsa2.priv -C primary2.ctx  -L policy.dat
tpm2_load -C primary2.ctx -u rsa2.pub -r rsa2.priv -c rsa2.ctx

## finally make the key persistent
tpm2_evictcontrol -C o -c rsa2.ctx 0x81008004
```

Then,

```bash
cd example/
go run policy/main.go --persistentHandle=0x81008004
```


For more information, see (TPM2 Policy)[https://github.com/salrashid123/tpm2/tree/master/policy]
