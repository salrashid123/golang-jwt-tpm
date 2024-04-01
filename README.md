# golang-jwt for Trusted Platform Module (TPM)

This is just an extension for [go-jwt](https://github.com/golang-jwt/jwt#extensions) i wrote over thanksgiving that allows creating and verifying JWT tokens where the private key is embedded inside a [Trusted platform module](https://en.wikipedia.org/wiki/Trusted_Platform_Module).

You can use this library to sign and verify a JWT using the standard `go-jwt` library semantics.

This library also includes a utility function to create an RSA key inside a TPM and also print its public key in `RSA` and `JWK` formats.

Using a TPM to sign or encrypt anything has some very specific applications which i will not go into it much (if your'e reading this, you probably already know).  If a JWT is signed by a TPM and if the key that was used was setup in a specific format, the verifier can be sure that the JWT was signed by that TPM.

For example, you can use a TPM to generate an RSA key with specifications that "this key was generated on a TPM with characteristics such that it cannot get exportable outside the TPM"..very necessarily, the RSA private key will never exist anywhere else other than in that TPM.

How a you trust that a specific RSA or ECC key happens to be from a given TPM with a given specification set is a rather complicated protocol that is also not covered in this repo.  The specific trust protocol is called [TPM Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html).

This repo assumes the verifier of the JWT has already established that the RSA key that is being used to sign the JWT

>> this repo is not supported by google

Much of this implementation is templated from [gcp-jwt-go](https://github.com/someone1/gcp-jwt-go)

### Supported Key Types

The following types are supported

* `RS256`
* `ES256`

against the TPM `OWNER` hierarchy

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
   --image=debian-11 --image-project=debian-cloud

# ssh to VM

## this library uses go-tpm-tools which...unfortunately requires the following ONLY on the system
## that generates the JWT;  any verifier just needs the public key
##  https://github.com/google/go-tpm-tools#trousers-errors-when-building-server
apt-get update && apt-get install gcc git libtspi-dev
```

Once on the VM, create a key on TPM (if you already have an existing key on TPM, you can acquire a handle using `go-tpm-tools`).  For now, create a key

The key created is _persisted_ at a handle (default `0x81008001`) and you can pick any defined in pg 15 of [Registry of Reserved TPM 2.0 Handles and Localities](https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf)


```bash
$ git clone https://github.com/salrashid123/golang-jwt-tpm.git
$ cd util/
```

generate RSA

```bash
$ go run keycreate.go  --persistentHandle 0x81008001 --keyAlg=RSA

    2024/03/31 12:15:45 ======= Init  ========
    2024/03/31 12:15:45      key Name: 
    b094a27c079ca2473446f59830a15963dc62731b267584a2e5b620cf74910f82
    2024/03/31 12:15:45 ======= PersistHandle (k) ========
    2024/03/31 12:15:45      PublicKey: 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx9mk8rvVB+Lf9RO1mkEV
    jxZ4gUqLx/zk3k5gbCswk7POzR3t5J8gQBZbY55ieW2IcnqyK0lf/uW+d6fgI+bT
    34FtSlkk5QBcu5IEIyO9WZa/VpMf777ZZ0v/TXJUsVhpFMOj+Kk4WpaDkxRZ2KW0
    /PiM4BKm/PVE7X17Tz2VZwJuBDXIGUv4e+oSK84mbpzVGppGn6gF10LbGdbj64+K
    +0LkXuelwtDkOXME/AndpPHsuEfIf3UgC48bipU5L/CTurCjJGeGcMdJeMxPMmSt
    ilIqDUOlIik+vhETpoOvtd3mX80hxinG07KRpb6Gl04AS1fFViJkOSn5mKVUpjCj
    VQIDAQAB
    -----END PUBLIC KEY-----
    2024/03/31 12:15:45 Public Key written to: key.pem
    JWK Format:
    {
      "e": "AQAB",
      "kid": "WE1PnTXj03tE0bfU1BfSFh9J/+GQ955hxHSvXjK4uhE",
      "kty": "RSA",
      "n": "x9mk8rvVB-Lf9RO1mkEVjxZ4gUqLx_zk3k5gbCswk7POzR3t5J8gQBZbY55ieW2IcnqyK0lf_uW-d6fgI-bT34FtSlkk5QBcu5IEIyO9WZa_VpMf777ZZ0v_TXJUsVhpFMOj-Kk4WpaDkxRZ2KW0_PiM4BKm_PVE7X17Tz2VZwJuBDXIGUv4e-oSK84mbpzVGppGn6gF10LbGdbj64-K-0LkXuelwtDkOXME_AndpPHsuEfIf3UgC48bipU5L_CTurCjJGeGcMdJeMxPMmStilIqDUOlIik-vhETpoOvtd3mX80hxinG07KRpb6Gl04AS1fFViJkOSn5mKVUpjCjVQ"
    }

# or with tpm2_tools
# tpm2_createprimary -C e -c primary.ctx
# tpm2_create -G rsa -u key.pub -r key.priv -C primary.ctx
# tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
# tpm2_evictcontrol -C o -c key.ctx 0x81008001
```

or ECC

```bash
$ go run keycreate.go  --persistentHandle 0x81008002 --keyAlg=ECC

    2024/03/31 12:15:53 ======= Init  ========
    2024/03/31 12:15:53      key Name: 
    c2db8cb8dd2b93adafd5f0eb9d7b8b6ab1f7f9f68c7d120489ae447732b94d23
    2024/03/31 12:15:53 ======= PersistHandle (k) ========
    2024/03/31 12:15:53      PublicKey: 
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhgCQBactv03N+4n0En2n5YdzKdBM
    Xc9bk/pCN8Bpkd5XtKFHhsolNO7ri9xOGwrXmT+PfQu7yEjvqPbnQs8e4A==
    -----END PUBLIC KEY-----
    2024/03/31 12:15:53 Public Key written to: key.pem
    JWK Format:
    {
      "crv": "P-256",
      "kid": "K2kf1bx2NHp31GtRjnggWyRfYqZbhK81U8AxY6UwPto",
      "kty": "EC",
      "x": "hgCQBactv03N-4n0En2n5YdzKdBMXc9bk_pCN8Bpkd4",
      "y": "V7ShR4bKJTTu64vcThsK15k_j30Lu8hI76j250LPHuA"
    }

# tpm2_createprimary -C e -c primary.ctx
# tpm2_create -G ecc -u key.pub -r key.priv -C primary.ctx
# tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
# tpm2_evictcontrol -C o -c key.ctx 0x81008002    
```


If the handle is already defined, you can evict it with `-evict` flag (equivalent of `tpm2_evictcontrol -C o -c  0x81008001`)

The output of the create command make a persistent key at the value of `persistentHandle`.  The output also includes `key.pem` (the public `RSA`)

Note that the output shows the PublicKey in RSA and JWK formats

Now create a test JWT and verify it with an RSA key that is extracted from a TPM and also directly, a cached key. 

Now issue a JWT and notice the public key matches what we saved to the TPM:

```bash
cd example/

$ go run main.go --persistentHandle 0x81008001 --template cached --keyAlg=RSA

    2024/03/31 12:16:55 ======= Init  ========
    2024/03/31 12:16:56      Load SigningKey from template cached 
    2024/03/31 12:16:56      Signing PEM 
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx9mk8rvVB+Lf9RO1mkEV
    jxZ4gUqLx/zk3k5gbCswk7POzR3t5J8gQBZbY55ieW2IcnqyK0lf/uW+d6fgI+bT
    34FtSlkk5QBcu5IEIyO9WZa/VpMf777ZZ0v/TXJUsVhpFMOj+Kk4WpaDkxRZ2KW0
    /PiM4BKm/PVE7X17Tz2VZwJuBDXIGUv4e+oSK84mbpzVGppGn6gF10LbGdbj64+K
    +0LkXuelwtDkOXME/AndpPHsuEfIf3UgC48bipU5L/CTurCjJGeGcMdJeMxPMmSt
    ilIqDUOlIik+vhETpoOvtd3mX80hxinG07KRpb6Gl04AS1fFViJkOSn5mKVUpjCj
    VQIDAQAB
    -----END PUBLIC KEY-----
    TOKEN: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTE4ODc0NzYsImlzcyI6InRlc3QifQ.gRu9qBKYrNa8zW_Q1XxpbDLTQy0Gbq_ns9EPTAS9sl0qe6srT54zxjE0TOWnzhiS1sk8m4v7COfITKMSt7xYGk_-3gOmESBfofvQvoAQHyahZ920B2RrPXiKCLdf2T9LM2Dt_T_g-cAWdVuCo4yThY8SG5suvwpvqxMsBl-YpymLl8LrazYW7eRn3z3nP3HM3vTdMJji3DVALsROgjNXuVndcqzvkNFv78AXZaX2tXs1KoMgf5e_EhFjFqWzguQkma6HF-2yc6Bot-GTO_gVQOaOBvM8aR4sJVhUDVYKObwG80tCaIrQWF9V4dGIpkTECBAun3YmnZkW1Wzlk7WnVw
    2024/03/31 12:16:56      verified with TPM PublicKey
    2024/03/31 12:16:56      verified with exported PubicKey


$ go run main.go --persistentHandle 0x81008002 --template cached --keyAlg=ECC

    2024/03/31 12:17:04 ======= Init  ========
    2024/03/31 12:17:04      Load SigningKey from template cached 
    2024/03/31 12:17:04      Signing PEM 
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhgCQBactv03N+4n0En2n5YdzKdBM
    Xc9bk/pCN8Bpkd5XtKFHhsolNO7ri9xOGwrXmT+PfQu7yEjvqPbnQs8e4A==
    -----END PUBLIC KEY-----
    TOKEN: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTE4ODc0ODQsImlzcyI6InRlc3QifQ.IikblaLKzoDAOzdYi0X4IHgjAPtY8OLI0HlPN5Oux0ujUAp0BifVn3mrP2MnwpYyLvngfOPhGoAza2ZSY7N1tg
    2024/03/31 12:17:04      verified with TPM PublicKey
    2024/03/31 12:17:04      verified with exported PubicKey
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

to use, just import the library configure the TPM.  Remember to set the override so that the correct `alg` is defined in the JWT .

You must have a key already defined and persisted to NV (transient keys not supported)

### Attestation Key

If you want to use the Attestation key, just get the handle in the same way. 

The example cited here uses a generated Attestation key.

If your'e on a GCP Shielded VM, it comes with a built in (pregenerated)  AK.  To use the GCP AK, uncomment `k, err = client.GceAttestationKeyRSA(rwc)` in the example.go file.  For example:

```bash
$ go run main.go --persistentHandle 0x81008001 --template akrsa --keyAlg=RSA

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

The specific advantage of GCP and `GceAttestationKeyRSA` is you can also get the AK via API

```bash
$ gcloud compute instances get-shielded-identity instance-1

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

using tpm2_tools:

```bash
openssl rsa -in private.pem -pubout
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem

tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
tpm2_import -C primary.ctx -G rsa -i private.pem -u key.pub -r key.prv
tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
tpm2_evictcontrol -C o -c key.ctx 0x81008003
```


In the following, we persisted an RSA key (private.pem) into key `0x81008003`

```bash
$ openssl rsa -in private.pem -pubout

    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzozz2jOLieHBMrEobKaf
    LGNKP5DWGTGU/C4md2klDJsrwRVsTnM0D1hdH4h3Xho5iM4Llz5Us6TAqzkO4sGg
    2iPfWz9C6P+j8ajRIK46KB9UAdd8+nGoKQzDJ8tpF/jFYyev7kHhPzbibK1GsrDq
    u2+zZuNpp2Jv62iTDK160cmonADRzTB7GQMgFWdvSr0YvscwhH3+17Thph4tRXF8
    RDdumg+4TKiAKRVDSw8thdCapwLMz/5bh9Ourr0QNqHOJqNEfayg0sS9ugqbu2nG
    FMyPtlMojcpTehujjms61MrDOwSYPq/boK24Y+2HlRyXYooLnzp/pKq8nbdht+Fi
    OwIDAQAB
    -----END PUBLIC KEY-----
```

Reading specifications using tpm2_tools and verify that the private key exists on the TPM:

```bash
$ tpm2_readpublic -Q -c 0x81008003 -f pem -o imported_key.pem

$ cat imported_key.pem 

    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzozz2jOLieHBMrEobKaf
    LGNKP5DWGTGU/C4md2klDJsrwRVsTnM0D1hdH4h3Xho5iM4Llz5Us6TAqzkO4sGg
    2iPfWz9C6P+j8ajRIK46KB9UAdd8+nGoKQzDJ8tpF/jFYyev7kHhPzbibK1GsrDq
    u2+zZuNpp2Jv62iTDK160cmonADRzTB7GQMgFWdvSr0YvscwhH3+17Thph4tRXF8
    RDdumg+4TKiAKRVDSw8thdCapwLMz/5bh9Ourr0QNqHOJqNEfayg0sS9ugqbu2nG
    FMyPtlMojcpTehujjms61MrDOwSYPq/boK24Y+2HlRyXYooLnzp/pKq8nbdht+Fi
    OwIDAQAB
    -----END PUBLIC KEY-----


$ go run main.go --persistentHandle 0x81008003 --template cached --keyAlg=RSA

      2024/03/31 12:48:14 ======= Init  ========
      2024/03/31 12:48:14      Load SigningKey from template cached 
      2024/03/31 12:48:14      Signing PEM 
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzozz2jOLieHBMrEobKaf
      LGNKP5DWGTGU/C4md2klDJsrwRVsTnM0D1hdH4h3Xho5iM4Llz5Us6TAqzkO4sGg
      2iPfWz9C6P+j8ajRIK46KB9UAdd8+nGoKQzDJ8tpF/jFYyev7kHhPzbibK1GsrDq
      u2+zZuNpp2Jv62iTDK160cmonADRzTB7GQMgFWdvSr0YvscwhH3+17Thph4tRXF8
      RDdumg+4TKiAKRVDSw8thdCapwLMz/5bh9Ourr0QNqHOJqNEfayg0sS9ugqbu2nG
      FMyPtlMojcpTehujjms61MrDOwSYPq/boK24Y+2HlRyXYooLnzp/pKq8nbdht+Fi
      OwIDAQAB
      -----END PUBLIC KEY-----
      TOKEN: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTE4ODkzNTQsImlzcyI6InRlc3QifQ.loMcBdqlVTJS8KzPYQhtcxSm83gnwFIurnk3WLkx_G_skrq4iqyyHOpVJDyqgMuRAxWz1HC-SoNiml1TCwvqTXs7SZ9tGkS6dFd4PDIQvtKh8c20bwK-rMydqXJfRopjkdD_xzvchdqacIxUjDIedFNXwX21Znxq3OAH1YDkT6LNYvIzFEWlq-fMX9dyird5PmgvzVEYnd8X3QNBU78drNEwTHsjhmJotEj2tpfxtg86Eg27K3AQfjOYgvzMoHTo1-AEYbNh8nIyGIg_DXQbbzSwbBqgn8HhqEADwBbgkyq2O0NJLSf2FjkDieTcSQgFKvknsF8JUcw0c7vs_bEkkw
      2024/03/31 12:48:14      verified with TPM PublicKey
      2024/03/31 12:48:14      verified with exported PubicKey
```

You can also see how to load the entire chain here [Loading TPM key chains](https://github.com/salrashid123/tpm2/context_chain)


