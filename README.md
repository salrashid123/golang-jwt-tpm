# golang-jwt for Trusted Platform Module (TPM)

This is just an extension for [go-jwt](https://github.com/golang-jwt/jwt#extensions) i wrote over thanksgiving that allows creating and verifying JWT tokens where the private key is embedded inside a [Trusted platform module](https://en.wikipedia.org/wiki/Trusted_Platform_Module).

You can use this library to sign and verify a JWT using the standard `go-jwt` library semantics.

This library also includes a utility function to create an RSA key inside a TPM and also print its public key in `RSA` and `JWK` formats.

Using a TPM to sign or encrypt anything has some very specific applications which i will not go into it much (if your'e reading this, you probably already know).  If a JWT is signed by a TPM and if the key that was used was setup in a specific format, the verifier can be sure that the JWT was signed by that TPM.

For example, you can use a TPM to generate an RSA key with specifications that "this key was generated on a TPM with characteristics such that it cannot get exportable outside the TPM"..very necessarily, the RSA private key will never exist anywhere else other than in that TPM.

How a you trust that a specific RSA key happens to be from a given TPM with a given specification set is a rather complicated protocol that is also not covered in this repo.  The specific trust protocol is called [TPM Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html).

This repo assumes the verifier of the JWT has already established that the RSA key that is being used to sign the JWT

>> this repo is not supported by google

Much of this implementation is inspired templated form [gcp-jwt-go](https://github.com/someone1/gcp-jwt-go)

### Supported Key Types

The following types are supported

* `RSA+SHA256`

### Usage

Use this library to issue JWTs in a way compatible with golang-jwt library.  The difference is that the caller must initialize a `client.Key` object from [go-tpm-tools](https://github.com/google/go-tpm-tools):

```golang
import (
	"github.com/golang-jwt/jwt"
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

claims := &jwt.StandardClaims{
	ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
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
   --image=debian-10-buster-v20210916 --image-project=debian-cloud

# ssh to VM

## this library uses go-tpm-tools which...unfortunately requires the following ONLY on the system
## that generates the JWT;  any verifier just needs the public key
##  https://github.com/google/go-tpm-tools#trousers-errors-when-building-server
apt-get update && apt-get install gcc libtspi-dev
```

Once on the VM, create a key on TPM (if you already have an existing key on TPM, you can acquire a handle using `go-tpm-tools`).  For now, create a key


The key created is _persisted_ at a handle (default `0x81008001`) and you can pick any defined in pg 15 of [Registry of Reserved TPM 2.0 Handles and Localities](https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf)


```log
$ git clone https://github.com/salrashid123/golang-jwt-tpm.git
$ cd util

$ go run keycreate.go  --persistentHandle 0x81008001

    2023/08/27 19:41:41 ======= Init  ========
    2023/08/27 19:41:41      key Name: 
    b96d36c1514a1e00f0213c5f52f5c74e5d439f5b333360330ef5695ec27d9100
    2023/08/27 19:41:41 ======= PersistHandle (k) ========
    2023/08/27 19:41:41      PublicKey: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvenLjnHCMRr9XEcYZ7rR
    qMUF5jAdFXqumrKG+uVYLR/7VNJAF3XgQRrEF/SjTMIwYXgzk0w6JK+fVVPFjiRf
    7Jnm4eEvd3uBXHTs3JSosQ8E6DvArSJ7RyXslj7B/l1Fth/a2CUuMngY+KD7e+bL
    iLnZj7P16MVaUQtwHIlcE5wctW0o1ZomOUqMyffn1pCKtgQ3Sgh/d2/LHH+xIzbH
    fNzqXLVVvZ0yuIq8efuCcvEDj5ad5r7eJ330lVkLF12p9gzYVDzhVTpvr2GCHiab
    GhqVxDAS6lUb+H6IvayqlyCw/HLyqJ0+uldz0FHTusUsYkFJB5a7HF3vTG+vzhzq
    /wIDAQAB
    -----END PUBLIC KEY-----
    2023/08/27 19:41:41 Public Key written to: key.pem
    JWK Format:
    {
      "e": "AQAB",
      "kid": "OalzExXmgY8n+ot1Fuq3W3RdaMfXwvz6L/rcZMVrQfU",
      "kty": "RSA",
      "n": "venLjnHCMRr9XEcYZ7rRqMUF5jAdFXqumrKG-uVYLR_7VNJAF3XgQRrEF_SjTMIwYXgzk0w6JK-fVVPFjiRf7Jnm4eEvd3uBXHTs3JSosQ8E6DvArSJ7RyXslj7B_l1Fth_a2CUuMngY-KD7e-bLiLnZj7P16MVaUQtwHIlcE5wctW0o1ZomOUqMyffn1pCKtgQ3Sgh_d2_LHH-xIzbHfNzqXLVVvZ0yuIq8efuCcvEDj5ad5r7eJ330lVkLF12p9gzYVDzhVTpvr2GCHiabGhqVxDAS6lUb-H6IvayqlyCw_HLyqJ0-uldz0FHTusUsYkFJB5a7HF3vTG-vzhzq_w"
    }

```


If the handle is already defined, you can evict it with `-evict` flag (equivalent of `tpm2_evictcontrol -C o -c  0x81008001`)

The output of the create command make a persistent key at the value of `persistentHandle`.  The output also includes `key.pem` (the public `RSA`)

Note that the output shows the PublicKey in RSA and JWK formats

Now create a test JWT and verify it with an RSA key that is extracted from a TPM and also directly, a cached key. 

```log
$ cd examples/
$ go run main.go --persistentHandle 0x81008001 --template cached

    2023/08/27 20:04:09 ======= Init  ========
    2023/08/27 20:04:09      Load SigningKey from template cached 
    2023/08/27 20:04:09      Signing PEM 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvenLjnHCMRr9XEcYZ7rR
    qMUF5jAdFXqumrKG+uVYLR/7VNJAF3XgQRrEF/SjTMIwYXgzk0w6JK+fVVPFjiRf
    7Jnm4eEvd3uBXHTs3JSosQ8E6DvArSJ7RyXslj7B/l1Fth/a2CUuMngY+KD7e+bL
    iLnZj7P16MVaUQtwHIlcE5wctW0o1ZomOUqMyffn1pCKtgQ3Sgh/d2/LHH+xIzbH
    fNzqXLVVvZ0yuIq8efuCcvEDj5ad5r7eJ330lVkLF12p9gzYVDzhVTpvr2GCHiab
    GhqVxDAS6lUb+H6IvayqlyCw/HLyqJ0+uldz0FHTusUsYkFJB5a7HF3vTG+vzhzq
    /wIDAQAB
    -----END PUBLIC KEY-----
    TOKEN: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2OTMxNjY3MDksImlzcyI6InRlc3QifQ.OqrRO1MRQda3dLneezZQ71jef24ox2y-UIhRcR9fokcAjIrk5sQxqmCECJ8Dn2IIB2v_M2MLFuwTX8XZ-jtJCSZRyu0FhkHod1N_FaBdHcSBOdiRKHwcdHjkPnmyDtv3wjCrJd4H-BCoMt1giALQiQ-V5fEypcmVbQVii1i8W8ezCqpwyQ3MwHvqK5T4ycD__FY2G6-IYozmjbZXLVXoVSaPm3Ij-ihu3rkAneBHeL774kX4weK8LbeMIF3vuvRZjTTeT2ledV7Jh2Sicz7SsVm8wBj4Whc1WVWq2gwrOUaTFmcmXsEkBBJ9WZ4gjyCc7EmHOcmbVzSRDqYIPO5axg
    2023/08/27 20:04:09      verified with TPM PublicKey
    2023/08/27 20:04:09      verified with exported PubicKey
```

Notice the public key matches the one we saved to the handle

The JWT is formatted as:


```json
{
  "alg": "RS256",
  "typ": "JWT"
}
{
  "exp": 1693166709,
  "iss": "test"
}
```


to use, just import the library configure the TPM.  Remember to set the override so that the correct `alg` is defined in the JWT .

You must have a key already defined and persisted to NV (transient keys not supported)

### Attestation Key

If you want to use the Attestation key, just get the handle in the same way. 

The example cited here uses GCP Shielded VM which means we an use `k, err = client.GceAttestationKeyRSA(rwc)`

```log
$ go run main.go --persistentHandle 0x81008001 --template ak
    2023/08/27 20:05:08 ======= Init  ========
    2023/08/27 20:05:08      Load SigningKey from template ak 
    2023/08/27 20:05:08      Signing PEM 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoxPZjkDnKfUZ1XZXs3oP
    t3B1j5H/xjDuV7UP8BsddHrAdUDEZYfF4OJr05zF4Wr80WD1GEzZmLPinAqzSGoR
    pXfDETYGDMB55vHmS/+fFvsIiEHpH6JPFHFUpCLxlszLKSG5oGkcTp1ONe2GcyxQ
    MQBPrf0/3PrcE1ze8v23Qj6k0ZFw4+X9qXuJe0cj/pshyt5Ckmq2ishxM0WhJLtM
    g7B+Rn3yDx5RWmE6Zduh9e8ndViuDPW7vFjuITYOXsyFdUINPyUmPQLU14wB+k03
    MRqN84PdLmcwK72gnC2gTBSox9cj9cpuuHFOmpUPOYWfzVBsRc9BXTR36lPfmalf
    gQIDAQAB
    -----END PUBLIC KEY-----
    TOKEN: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2OTMxNjY3NjgsImlzcyI6InRlc3QifQ.l7SaJBvhKS3dywmWE6dmr91WV119lvs2FEzUXgewClAz3RiGx0Nhe7n2YICBzXNccZ3MiNJgMdfjPpLbbxY-YWAAm0FRGXZ2AqPs5lysNqtCtFU3w4buTxFsqy5shMsGb7hpGdWRJtyLRMWtWVhHUyr2fqmBhaHRldDQq30BjEvvviWlT0Dc_RHDkIXTz-DfS6UIvuc_LPbVksZwteyp0pLp9HsmXedqU9EcdUafi2W-m8JQ2_LLhmL7uBG2kzURgngnHfNPSgI4JvW2Wh56pexCJIINOVWmMXsT6BL-K2COiZQ2Trpg06WHtIF0-YPeT-bbewqIQZHCMoESt6qSNQ
    2023/08/27 20:05:08      verified with TPM PublicKey
    2023/08/27 20:05:08      verified with exported PubicKey
```

The specific advantage of GCP is you can also get the AK via API

```bash
$ gcloud compute instances get-shielded-identity instance-1
encryptionKey:
  ekPub: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvcQAd75FuBOhFklsqSU2
    uHReUfHr99kGE/is6Dj5U0DyZgUmx9H1B/QrjfXeSpJpodelTlBxf2hlue7ffdnc
    2YiKpsvSetGVHZWX7NEBGraIyeaZYZoouwnwd+cYj9UAkT0vRjMEiZ1bdcRVwQJK
    YvYR3PsTD/4j+CGuzMQH//i06yREVs3B8RxCyPut75b9KkMNzU+tdh0iJc5oDVdl
    5CkcYgWzhtvuz1dlwe771UQ2mb5Vi5qXO6/6L2IZQGUWl3UJXPkFdvCzKzDEuwrb
    wu+5SiWkbnAiQvAJVhRF1uL8KsUEKFo2R//d5c8I6OREuNKfjo842MuuCxaPmeAe
    +wIDAQAB
    -----END PUBLIC KEY-----
kind: compute#shieldedInstanceIdentity
signingKey:
  ekPub: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoxPZjkDnKfUZ1XZXs3oP
    t3B1j5H/xjDuV7UP8BsddHrAdUDEZYfF4OJr05zF4Wr80WD1GEzZmLPinAqzSGoR
    pXfDETYGDMB55vHmS/+fFvsIiEHpH6JPFHFUpCLxlszLKSG5oGkcTp1ONe2GcyxQ
    MQBPrf0/3PrcE1ze8v23Qj6k0ZFw4+X9qXuJe0cj/pshyt5Ckmq2ishxM0WhJLtM
    g7B+Rn3yDx5RWmE6Zduh9e8ndViuDPW7vFjuITYOXsyFdUINPyUmPQLU14wB+k03
    MRqN84PdLmcwK72gnC2gTBSox9cj9cpuuHFOmpUPOYWfzVBsRc9BXTR36lPfmalf
    gQIDAQAB
    -----END PUBLIC KEY-----
```

also see

* [Read EK keys on GCE](https://github.com/salrashid123/tpm2/tree/master/gcp_ek_ak)
* [Sign with AK saved to NV](https://github.com/salrashid123/tpm2/blob/master/ak_sign_nv)
* [Read NV](https://github.com/salrashid123/tpm2/tree/master/nv)

### Imported Key

If you want to [import an external RSA key to the TPM](https://github.com/salrashid123/tpm2/tree/master/tpm_import_external_rsa#importing-an-external-key), you will need to define a persistent handle as well.

You can also see how to load the entire chain here [Loading TPM key chains](https://github.com/salrashid123/tpm2/context_chain)

In the following, we persisted an RSA key (private.pem) into key `0x81008000`

```bash
$ openssl rsa -in private.pem -pubout

-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0gky/duzKvB6EgSedqTm
oCEHpRU2vxaPa6FcrruQzBs3rOh+2wdSciq7C96hWuQGM4Xevxm47a6tBswm1zsz
QOOzbbHvfncUbcslGz2KApPiKbByk4DdPzdw1o7ys0xUIaNgJLOp03WJKymJSkXF
Wu8EQD4PtX6Rg8BZyDvuctKXuFL7G/xCNwlzFFF3aur7GHwIskG3vZaisx1eR0jy
oBTynQMeTggLW6OLdZP260Gxj1nCtrWUbvmcQU0XxGQlSa+/edEtNzeW1rxiu9vU
dHXx5OU+074UGjdHkEPb28UBJcR+etmMA2sqwkZAh/Ji+ZxQTiq2YYY8XcaouAqa
gQIDAQAB
-----END PUBLIC KEY-----
```

Reading specifications using tpm2_tools and verify that the private key exists on the TPM:

```bash
$ tpm2_readpublic -Q -c 0x81010002 -f pem -o imported_key.pem

$ cat imported_key.pem 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0gky/duzKvB6EgSedqTm
oCEHpRU2vxaPa6FcrruQzBs3rOh+2wdSciq7C96hWuQGM4Xevxm47a6tBswm1zsz
QOOzbbHvfncUbcslGz2KApPiKbByk4DdPzdw1o7ys0xUIaNgJLOp03WJKymJSkXF
Wu8EQD4PtX6Rg8BZyDvuctKXuFL7G/xCNwlzFFF3aur7GHwIskG3vZaisx1eR0jy
oBTynQMeTggLW6OLdZP260Gxj1nCtrWUbvmcQU0XxGQlSa+/edEtNzeW1rxiu9vU
dHXx5OU+074UGjdHkEPb28UBJcR+etmMA2sqwkZAh/Ji+ZxQTiq2YYY8XcaouAqa
gQIDAQAB
-----END PUBLIC KEY-----

```

Now issue a JWT and notice the public key matches what we saved to the TPM:

```bash
$ go run main.go --persistentHandle 0x81010002 --template cached

    2023/08/27 20:32:08 ======= Init  ========
    2023/08/27 20:32:08      Load SigningKey from template cached 
    2023/08/27 20:32:08      Signing PEM 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0gky/duzKvB6EgSedqTm
    oCEHpRU2vxaPa6FcrruQzBs3rOh+2wdSciq7C96hWuQGM4Xevxm47a6tBswm1zsz
    QOOzbbHvfncUbcslGz2KApPiKbByk4DdPzdw1o7ys0xUIaNgJLOp03WJKymJSkXF
    Wu8EQD4PtX6Rg8BZyDvuctKXuFL7G/xCNwlzFFF3aur7GHwIskG3vZaisx1eR0jy
    oBTynQMeTggLW6OLdZP260Gxj1nCtrWUbvmcQU0XxGQlSa+/edEtNzeW1rxiu9vU
    dHXx5OU+074UGjdHkEPb28UBJcR+etmMA2sqwkZAh/Ji+ZxQTiq2YYY8XcaouAqa
    gQIDAQAB
    -----END PUBLIC KEY-----
    TOKEN: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2OTMxNjgzODgsImlzcyI6InRlc3QifQ.uzvr5U4IK-iglm--BdOa67PZLKGdp7QZgNqYYtoRgFDxDzMB2HV7EXyyH-1vXOMWEq4b-kfowDY6IVppZTz57Mpf6DTQukRzWNfNktLdPXjvYaBTS_DFvhuhrwPonu6QQZMhSSxcujS-Zb5bs0_HxpIslLSgCoBqB31ZTnKcUpal4SIwUecUKDDB8wKXST2Skg8moh7GEWLh6uPTsLZ1EgrF33_dVB-1HteIcQOgyDlPsL8GLCEfG92gOmquDGYPSOy9q_Nz6wXPT-ceupb1jJiGJcj4zUJ_8bw0Q1QnUqYEp7S-aYJ8wNx2yrAqEiCt7tAAKNrkgl6HgKwOCm-t1g
    2023/08/27 20:32:08      verified with TPM PublicKey
    2023/08/27 20:32:08      verified with exported PubicKey
```