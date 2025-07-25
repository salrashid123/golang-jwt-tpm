# golang-jwt for Trusted Platform Module (TPM)

This is just an extension for [go-jwt](https://github.com/golang-jwt/jwt#extensions) i wrote over thanksgiving that allows creating and verifying JWT tokens where the private key is embedded inside a [Trusted platform module](https://en.wikipedia.org/wiki/Trusted_Platform_Module).

You can use this library to sign and verify a JWT using the standard `go-jwt` library semantics.

Using a TPM to sign or encrypt anything has some very specific applications which i will not go into it much (if your'e reading this, you probably already know).  If a JWT is signed by a TPM and if the key that was used was setup in a specific format, the verifier can be sure that the JWT was signed by that TPM.

For example, you can use a TPM to generate an RSA key with specifications that "this key was generated on a TPM with characteristics such that it cannot get exportable outside the TPM"..very necessarily, the RSA private key will never exist anywhere else other than in that TPM.

How a you trust that a specific `RSA` or `ECC` key happens to be from a given TPM with a given specification set is a rather complicated protocol that is also not covered in this repo.  The specific trust protocol is called [TPM Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html).

Note that Google Cloud Confidential VMs already comes built in with an `x509` Attestation Key (AK).  This simplifies the need to do full remote Attestation for GCP instances (eg, you sign a JWT and verify that that signed JWT must have originated on a specific GCE VM (see the examples folder in  [gcp-vtpm-ek-ak](https://github.com/salrashid123/gcp-vtpm-ek-ak))

This repo assumes the verifier of the JWT has already established that the RSA key that is being used to sign the JWT

>> this repo is not supported by google

### Supported Key Types

The following types are supported

* `RS256`
* `PS256`
* `ES256`


### Usage

You need to first have an RSA or ECC key saved to a TPM and then specify its [go-tpm/tpm2.TPMHandle](https://pkg.go.dev/github.com/google/go-tpm@v0.9.0/tpm2#TPMHandle) with this library.

In the following, the Key is referenced as a [persistent or transient handle](https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf) or as a [PEM encoded TPM keyfile](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html)

Embedding a key to a TPM is out of scope of this repo but you can use [tpm2_tools](https://github.com/tpm2-software/tpm2-tools) as shown in the examples folder

Once the key is on a TPM (in this case, at handle `0x81008001`), usage is similar to:

#### with PersistentHandle

```golang
import (
	"github.com/golang-jwt/jwt/v5"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// initialize the TPM
rwc, err := tpm2.OpenTPM("/dev/tpmrm0")
defer rwc.Close()
rwr := transport.FromReadWriter(rwc)

var keyHandle tpm2.TPMHandle

// Load the key from either
// 1. persistent handle
keyHandle =  tpm2.TPMHandle(0x81008001)

config := &tpmjwt.TPMConfig{
	TPMDevice: rwc,
	Handle: keyHandle,
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

#### with KeyFile

```golang
import (
	"github.com/golang-jwt/jwt/v5"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
)

rwc, err := tpm2.OpenTPM("/dev/tpmrm0")
defer rwc.Close()
rwr := transport.FromReadWriter(rwc)

var keyHandle tpm2.TPMHandle

c, err := os.ReadFile("/path/to/tpmkey.pem")

key, err := keyfile.Decode(c)

primaryKey, err := tpm2.CreatePrimary{
	PrimaryHandle: tpm2.AuthHandle{
		Handle: tpm2.TPMHandle(key.Parent),
		Auth:   tpm2.PasswordAuth(nil),
	},
	InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)

regenKey, err := tpm2.Load{
	ParentHandle: tpm2.AuthHandle{
		Handle: primaryKey.ObjectHandle,
		Name:   tpm2.TPM2BName(primaryKey.Name),
		Auth:   tpm2.PasswordAuth(nil),
	},
	InPublic:  key.Pubkey,
	InPrivate: key.Privkey,
	}.Execute(rwr)

keyHandle = regenKey.ObjectHandle

// now load and use the key
config := &tpmjwt.TPMConfig{
	TPMDevice: rwc,
	Handle: keyHandle,
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

#### With EKParent

If the TPM key you are using to sign is transferred from another system, using either 

* [tpm2_duplicate](https://github.com/salrashid123/tpm2/tree/master/tpm2_duplicate)
* [tpmcopy: Transfer RSA|ECC|AES|HMAC key to a remote Trusted Platform Module (TPM)](https://github.com/salrashid123/tpmcopy)

you can initialize the parent for the EK and then custom policy handlers.  For example, see [example/go_keyfile_ekparent/](example/go_keyfile_ekparent/) folder which uses a reference to the  `tpmcopy` sample set to use a duplicated key with passphrase.  


#### With ContextChain
 
see [Reload context chain](https://github.com/salrashid123/tpm2/tree/master/context_chain)

---

#### Other JWT generators

- [golang-jwt for post quantum cryptography](https://github.com/salrashid123/golang-jwt-pqc)
- [golang-jwt for crypto.Signer](https://github.com/salrashid123/golang-jwt-signer)
- [golang-jwt for PKCS11](https://github.com/salrashid123/golang-jwt-pkcs11)

---

### Setup

To use this library, you need a TPM to issue a JWT (you do not need a TPM to verify; you just need the public key).

For simplicity, the following generates and embeds keys into a persistent handle using [tpm2_tools](https://github.com/tpm2-software/tpm2-tools).  (You are free to use any system to provision a key)

#### Key Generation 

Create RSA key at handle `0x81008001`, RSA-PSS handle at `0x81008004`; ECC at `0x81008005`

```bash
## RSA - no password
	printf '\x00\x00' > unique.dat
	tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

	tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx

	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008001

## rsa-pss
	printf '\x00\x00' > unique.dat
	tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

	tpm2_create -G rsa2048:rsapss:null -g sha256 -u key.pub -r key.priv -C primary.ctx  --format=pem --output=rsapss_public.pem

	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008004

## ecc
	printf '\x00\x00' > unique.dat
	tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

	tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx  --format=pem --output=ecc_public.pem

	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008005    
```

If you would rather generate a TPM based PEM file that is compatible with openssl

- using `tpm2_tools`:

```bash
	printf '\x00\x00' > unique.dat
	tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

	tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx

	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx

	tpm2_encodeobject -C primary.ctx -u key.pub -r  key.priv -o private.pem
```

- using `openssl`:

```bash
# export TPM2OPENSSL_TCTI="device:/dev/tpmrm0"

openssl genpkey --provider tpm2 --provider default -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
      -pkeyopt rsa_keygen_pubexp:65537 -out private.pem
```

giving

```bash
$ openssl rsa --provider tpm2 --provider default --inform PEM  -text -in private.pem 

Private-Key: (RSA 2048 bit, TPM 2.0)
Modulus:
    00:db:fc:0f:ba:1a:b0:a4:04:17:75:4d:c1:a9:7c:
    9e:58:a5:6e:d4:2d:19:09:f6:3b:58:a1:7f:e9:cd:
    6e:4a:23:12:52:c6:02:55:cd:c1:39:12:30:e8:b3:
    6a:a4:68:ad:00:6d:58:72:0f:72:ec:9c:5d:9d:b3:
    48:0a:40:ab:3f:eb:8a:a0:99:ce:ba:ac:8c:fd:79:
    af:08:6d:1b:a9:bc:40:6f:f9:ec:89:86:25:c8:11:
    c7:da:c4:92:99:96:24:b7:e1:26:73:35:8f:2d:16:
    43:f1:3c:c1:00:ca:62:ea:ff:89:05:ae:9e:ad:d6:
    dc:fc:38:72:6f:cb:c9:f6:c3:1c:be:3a:66:b3:f2:
    fb:cd:a4:64:ff:8f:2e:a4:ba:3b:a1:c5:c7:b6:f7:
    93:1f:c0:0a:fe:61:dd:08:34:8c:cc:20:fb:cd:eb:
    39:8f:38:61:0f:b6:3a:5a:15:3e:05:07:97:c6:c6:
    fb:c1:32:d7:cd:e9:6d:59:f9:6d:16:e6:a1:47:52:
    84:b5:5e:4b:9a:7b:7a:6a:98:43:52:3d:05:54:60:
    f3:8b:a5:66:0f:d8:26:2b:df:8b:76:68:c4:a7:dd:
    84:48:1b:39:1b:21:b9:14:d3:13:2c:53:a9:18:2e:
    0a:7d:b3:44:63:ad:1d:f6:5c:e5:48:2d:2f:9f:51:
    39:97
Exponent: 65537 (0x10001)
Object Attributes:
  fixedTPM
  fixedParent
  sensitiveDataOrigin
  userWithAuth
  sign / encrypt
Signature Scheme: PKCS1
  Hash: SHA256
writing RSA key
-----BEGIN TSS2 PRIVATE KEY-----
MIICFAYGZ4EFCgEDoAMBAQECBEAAAAEEggEaARgAAQALAAQAcgAAABAAFAALCAAA
AAAAAQDb/A+6GrCkBBd1TcGpfJ5YpW7ULRkJ9jtYoX/pzW5KIxJSxgJVzcE5EjDo
s2qkaK0AbVhyD3LsnF2ds0gKQKs/64qgmc66rIz9ea8IbRupvEBv+eyJhiXIEcfa
xJKZliS34SZzNY8tFkPxPMEAymLq/4kFrp6t1tz8OHJvy8n2wxy+Omaz8vvNpGT/
jy6kujuhxce295MfwAr+Yd0INIzMIPvN6zmPOGEPtjpaFT4FB5fGxvvBMtfN6W1Z
+W0W5qFHUoS1Xkuae3pqmENSPQVUYPOLpWYP2CYr34t2aMSn3YRIGzkbIbkU0xMs
U6kYLgp9s0RjrR32XOVILS+fUTmXBIHgAN4AIPSBINT5Q0p7+rHrG5Ve6VZOORTR
jVmOO9rtYz+OFkK8ABCsPnJhnE9vJFr+D4L9Vod65EaUd5EdJO8YtbzTScGf5q4w
3Kcaa2PZjWP2qWYYBKQ8sFVBFWUen6t8WXC9IgHaaN7KWg1ZFRgaRgg3WHWMfqtO
hcnqXG0gKndpbIT4YrylhEupQzrLsMDRBfmtnywFLI+1F2dJ+W20yvdYMSAdLo8H
K4233tKJXbo9FhNDkouiQFl4GYHPr55tVa+HLhnUJwv1UgAoOwx2KEDokprhP53v
pu2wv5H2obE=
-----END TSS2 PRIVATE KEY-----
```

Then run,

```bash
cd example/

## RS256
$ go run nopolicy/main.go --mode=rsa --persistentHandle=0x81008001 --tpm-path=/dev/tpmrm0

	2024/05/30 11:26:54 ======= Init  ========
	2024/05/30 11:26:54 primaryKey Name AAvaZWBJngiVUFq6Dg/Q7uBxAK3INE3G/GOsnm7v0TGujQ==
	2024/05/30 11:26:54      Signing PEM 
	-----BEGIN PUBLIC KEY-----
	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArYHlZpdRyRvxSdcM18as
	/j6UruSGKOYgUjpt05h8z0NienvEKlSt0YJxPm2hIQBQAvZ5oR5aLNVUMePd6XHF
	wjNAkaME9KJB9KAQPMrEv7+WWAuBq8ImPCziEeXLBnWR4Bj6CsqXFNNq/q/FfJZv
	/iLD9IKMqNz/ChPHDJ4ZNRZRUCyHUG6+IgYIovbqT/YzE0nhAlU2EU1tj2+SBOBV
	p2VeqMMXIMfJVXRWAFbi3nR8TtQ04TBbGGNaG/+WvKnruT5CuiQ+V8wvHGnV84ux
	TiVIQV2nt57dRTodbEuzpyxES3gs2sOqC6KRZNVJXnz2IugqdkItHjnwR2KvnUEn
	NwIDAQAB
	-----END PUBLIC KEY-----
	TOKEN: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzE3MDgyODc0fQ.ETa4wNzr-NkUN9VLyCS0_8ZJkSsHxd_xbLfHnRr-wtjdD8-XqlYJ7ehYZRC677u_tda3AHftS8uXlPN1jNnbw5sAq7E50IyS2LICExc6SHPuGrsh_O4GN1sM4Gbaxk-KjRYIlePFbiepc0liyEglan4gjEySBZMrIzItvKBEfq-sC092RysfARggnRgUxNf49zlYPX8jTYL2OW46cc2c4qOurnDQhWWSn4MqfcfMh932eMBqW_i1obIcD_LjlQxfmJ7-e1Dm2n86CyFEHWe0ANQ3ixEp8ybuLzbU_KB3wFtnXJMn_iifoKJPpzFMds5d5GdeW_jiikiB1Eb7PUChlg
	2024/05/30 11:26:54      verified with TPM PublicKey
	2024/05/30 11:26:54      verified with exported PubicKey



## PS256
$ go run nopolicy/main.go --mode=rsapss --persistentHandle=0x81008004 --tpm-path=/dev/tpmrm0

	2024/05/30 11:27:10 ======= Init  ========
	2024/05/30 11:27:10 primaryKey Name AAvaZWBJngiVUFq6Dg/Q7uBxAK3INE3G/GOsnm7v0TGujQ==
	2024/05/30 11:27:10      Signing PEM 
	-----BEGIN PUBLIC KEY-----
	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2oTpzfYtQvejOHPmlRUX
	/6jWaH31sbM50XfCPfQ0q622mcKr2Cg4imnw0NxtCz2sOHNef/xEUiSHL3HFrK0T
	49Iy0INLo4yl07iURx+/4uriKuLEgfEkDrLMQthDD/a853Q5CIjbcqmxEIm4oS0J
	mdSJwDNpksUwPRu96wGeD/NLVpF+uK/yVRAkAJnIu16cSKivN/f02CcHDaTg/qZg
	bRf9B/sBXQRrv4R+cZkgjK/dXMIpQz7SABgvIOWnvOwjQHFXdH7vrZLpxlPaL3T+
	QcJvm/Xk7nrzJCBsyGBPlMjtGv1W1933M5w96rBZqPTJAGKLHcE5BVdZSge1ZTW4
	kwIDAQAB
	-----END PUBLIC KEY-----
	TOKEN: eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzE3MDgyODkwfQ.PTWmvgLXE4oVVdNW_fZr5_BZbcYAghUfdyaFIYCmQHXqJ60alHeZX3w9Vr3p62bWtX7LrIKMrOMqKfhcUz92fBYcx2z1BY1Y3RS6VyP3FUgckH4puFA8kU6Z7bFalgqVGV03B3jnlpRyNZOhbtcEHgf4XplmP_5ZIykw8q6ekChwyYrCwu03-m10lH_R6q4YKC_LV4sjcsvV4ZCTnZWo07ggbv8NUWECr13wu7ChWaD8UrvsUdhXXGMGnS_xtqKKvQjSL5EqSjmp8_PO10CI2x0ZgKFYY4aqh_CFQr-lT5qzkIgv9R5GzLPCdaa8NBpWx2YaTore61miXXLxdiJFwg
	2024/05/30 11:27:10      verified with TPM PublicKey
	2024/05/30 11:27:10      verified with exported PubicKey


## ES356
$ go run nopolicy/main.go --mode=ecc --persistentHandle=0x81008005 --tpm-path=/dev/tpmrm0

	2024/05/30 11:27:35 ======= Init  ========
	2024/05/30 11:27:35 primaryKey Name AAvaZWBJngiVUFq6Dg/Q7uBxAK3INE3G/GOsnm7v0TGujQ==
	2024/05/30 11:27:35      Signing PEM 
	-----BEGIN PUBLIC KEY-----
	MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5UHzO3QR1iS+D4+5F8fwiYxigTlO
	eL0hcqOz4DDbhQtxBuYjnVD7tCgVLN0riqCSgjh150j9E9xSDi0E55dFug==
	-----END PUBLIC KEY-----
	TOKEN: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzE3MDgyOTE1fQ.rm2RNGLnmKbLkdZbrkBxyd674VPX-VtKODNLDQgea_W1IRSMtKIaFWDzkuap3NGTVqsF-A9sIkAGRCdqAqF4rQ
	2024/05/30 11:27:35      verified with TPM PublicKey
	2024/05/30 11:27:35      verified with exported PubicKey


### usign PEM Keyfile

$ go run go_keyfile_compat/main.go --in private.pem
	2025/03/28 13:22:44 ======= Init  ========
	2025/03/28 13:22:44 ======= createPrimary ========
	2025/03/28 13:22:44 ======= reading key from file ========
	2025/03/28 13:22:44 primaryKey Name AAszWKEUfjTt36Q2raCjVgIlRyNMycEExrNDfvDId6PXLQ==
	2025/03/28 13:22:44      Signing PEM 
	-----BEGIN PUBLIC KEY-----
	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2/wPuhqwpAQXdU3BqXye
	WKVu1C0ZCfY7WKF/6c1uSiMSUsYCVc3BORIw6LNqpGitAG1Ycg9y7JxdnbNICkCr
	P+uKoJnOuqyM/XmvCG0bqbxAb/nsiYYlyBHH2sSSmZYkt+EmczWPLRZD8TzBAMpi
	6v+JBa6erdbc/Dhyb8vJ9sMcvjpms/L7zaRk/48upLo7ocXHtveTH8AK/mHdCDSM
	zCD7zes5jzhhD7Y6WhU+BQeXxsb7wTLXzeltWfltFuahR1KEtV5Lmnt6aphDUj0F
	VGDzi6VmD9gmK9+LdmjEp92ESBs5GyG5FNMTLFOpGC4KfbNEY60d9lzlSC0vn1E5
	lwIDAQAB
	-----END PUBLIC KEY-----
	TOKEN: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzQzMTgyNjI0fQ.oq5rL_Az2k_RtW_TUBfTHpIoiLktsISmQTcrzJ_pWuyY386YRcCtVprWr_1qQqDjBNlg6K4wRoFzD_s_1qNIQErb2g_gTrQ2_7HE_jbHE6131PtiDwkB2mNWaaPK-kN2utXlzOnzJf3Ca6duOntALn5eS5cA8e9joSwu3FdXVMk2pKQZLiNZWmbPi_8HyjN2gjER_e1NnbGCGpKrGpFWefIlw6OPjx6ELqsZlkQexaISwgSbdPLI6Av134LTLMMz_YaTCBNWz4GZuYH9DL6XHkGjKB5yamn-tZWjodqoVgQcZWErUDtDruUwJ_LEX95nFHWSdfPrK7t6YmmA0P0OUQ
```

### Session Encryption

If you want to enable [session encryption](https://github.com/salrashid123/tpm2/tree/master/tpm_encrypted_session), you need to supply an external key you know to be associated with a TPM (eg an `Endorsement Key` handle).
 

```golang
	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}
	createEKRsp, err := createEKCmd.Execute(rwr)

	config := &tpmjwt.TPMConfig{
		TPMDevice: rwc,
		Handle: tpm2.TPMHandle(0x81008001),
		EncryptionHandle: createEKRsp.ObjectHandle,
	}
```

Once you do that, the bus traffic is also encrypted

### Imported Key

If you want to [import an external RSA key to the TPM](https://github.com/salrashid123/tpm2/tree/master/tpm_import_external_rsa#importing-an-external-key), you will need to define a persistent handle as well.

using `tpm2_tools`:

```bash
	openssl genrsa -out private.pem 2048
	openssl rsa -in private.pem -outform PEM -pubout -out public.pem

	tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
	tpm2_import -C primary.ctx -G rsa2048:rsassa:null -g sha256  -i private.pem -u key.pub -r key.prv
	tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008006
```

You can also see how to load the entire chain here [Loading TPM key chains](https://github.com/salrashid123/tpm2/context_chain)


#### With Session and Policy

If a key is bound to a Password or PCR policy, you can specify that inline during key initialization.

For example, the following has password policy bound:

eg, for Password Policy:

```golang
	keyPass := []byte("pass2")

	rpub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(*persistentHandle),
	}.Execute(rwr)

	p, err := tpmjwt.NewPasswordSession(rwr, []byte(keyPass))
	config := &tpmjwt.TPMConfig{
		TPMDevice: rwc,
		Handle: tpm2.TPMHandle(*persistentHandle),
		AuthSession: p,
	}
```

For PCR Policy:

```golang
	rpub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(*persistentHandle),
	}.Execute(rwr)

	p, err := tpmjwt.NewPCRSession(rwr, []tpm2.TPMSPCRSelection{
		{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(23),
		},
	})

	config := &tpmjwt.TPMConfig{
		TPMDevice: rwc,
		Handle: tpm2.TPMHandle(*persistentHandle),
		AuthSession: p,
	}
```

If you want to set those up using tpm2_tools:

```bash
## RSA - password

	printf '\x00\x00' > unique.dat
	tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx  -p pass1 -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

	tpm2_create -G rsa2048:rsassa:null -g sha256  -P pass1 -p pass2 -u key.pub -r key.priv -C primary.ctx
	tpm2_load -C primary.ctx -P pass1 -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008002

## RSA - pcr

	tpm2_pcrread sha256:23
	tpm2_startauthsession -S session.dat
	tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
	tpm2_flushcontext session.dat

	printf '\x00\x00' > unique.dat
	tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

	tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx  -L policy.dat
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008003
```

Then,

```bash
cd example/

## passwordAuth
$ go run policy_password/main.go --persistentHandle=0x81008002 --tpm-path=/dev/tpm0

## pcrAuth
$ go run policy_pcr/main.go --persistentHandle=0x81008003 --tpm-path=/dev/tpm0
```

Note, you can define your own policy for import too...just implement the "session" interface from the signer:

```golang
type Session interface {
	GetSession() (auth tpm2.Session, closer func() error, err error) // this supplies the session handle to the library
}
```

for example, for a PCR and [AuthPolicy](https://github.com/google/go-tpm/pull/359) enforcement (eg, a PCR and password), you can define a custom session callback

```golang
type MyPCRAndPolicyAuthValueSession struct {
	rwr      transport.TPM
	sel      []tpm2.TPMSPCRSelection
	password []byte
}

var _ Session = (*MyPCRAndPolicyAuthValueSession)(nil)

func NewPCRAndPolicyAuthValueSession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection, password []byte) (MyPCRAndPolicyAuthValueSession, error) {
	return MyPCRAndPolicyAuthValueSession{rwr, sel, password}, nil
}

func (p MyPCRAndPolicyAuthValueSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	var options []tpm2.AuthOption
	options = append(options, tpm2.Auth(p.password))

	sess, closer, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, options...)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	return sess, closer, nil
}
```

which you can call as:

```golang
	p, err := NewPCRAndPolicyAuthValueSession(rwr, []tpm2.TPMSPCRSelection{
		{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(uint(*pcr)),
		},
	}, []byte("testpswd"))

	config := &tpmjwt.TPMConfig{
		TPMDevice: rwc,
		Handle: tpm2.TPMHandle(*persistentHandle),
		AuthSession: p,
	}
```

### Using Simulator

If you down't want to run the tests on a real TPM, you can opt to use `swtpm` if its installed:

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

## run any TPM command
export TPM2TOOLS_TCTI="swtpm:port=2321"
tpm2_pcrread sha256:23
```

### Errors

- `tpmjwt: can't Sign: TPM_RC_SCHEME (parameter 2): unsupported or incompatible scheme`

   Possibly the key being used does not sepcify all the parameters encoded into the key.  For example, if you print the public part of the key you are using, it should contain a value for `scheme` and `scheme-halg`:
   
```bash
$ tpm2_print -t TPM2B_PUBLIC certs/rkey.pub
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign
  raw: 0x40072
type:
  value: ecc
  raw: 0x23
curve-id:
  value: NIST p256
  raw: 0x3
kdfa-alg:
  value: null
  raw: 0x10
kdfa-halg:
  value: (null)
  raw: 0x0
scheme:
  value: ecdsa
  raw: 0x18
scheme-halg:
  value: sha256
  raw: 0xb
sym-alg:
  value: null
  raw: 0x10
sym-mode:
  value: (null)
  raw: 0x0
sym-keybits: 0
x: 59b3788ca115ca1ef8fff9d3df49e44ec8121baae656188162d3924aab84e369
y: 570985ca93bcea21873616b59bc85f1273446caf352133d9ceb4d6315004a186
```

---

also see

- [Sign, Verify and decode using Google Cloud vTPM Endorsement and Attestation Key and Certificate](https://github.com/salrashid123/gcp-vtpm-ek-ak)
- [Sign with AK saved to NV (gce only)](https://github.com/salrashid123/tpm2/tree/master/ak_sign_nv)
- [go-tpm-tools.client.GceAttestationKeyRSA()](https://pkg.go.dev/github.com/google/go-tpm-tools/client#GceAttestationKeyRSA)

