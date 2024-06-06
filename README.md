# golang-jwt for Trusted Platform Module (TPM)

This is just an extension for [go-jwt](https://github.com/golang-jwt/jwt#extensions) i wrote over thanksgiving that allows creating and verifying JWT tokens where the private key is embedded inside a [Trusted platform module](https://en.wikipedia.org/wiki/Trusted_Platform_Module).

You can use this library to sign and verify a JWT using the standard `go-jwt` library semantics.

Using a TPM to sign or encrypt anything has some very specific applications which i will not go into it much (if your'e reading this, you probably already know).  If a JWT is signed by a TPM and if the key that was used was setup in a specific format, the verifier can be sure that the JWT was signed by that TPM.

For example, you can use a TPM to generate an RSA key with specifications that "this key was generated on a TPM with characteristics such that it cannot get exportable outside the TPM"..very necessarily, the RSA private key will never exist anywhere else other than in that TPM.

How a you trust that a specific `RSA` or `ECC` key happens to be from a given TPM with a given specification set is a rather complicated protocol that is also not covered in this repo.  The specific trust protocol is called [TPM Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html).

This repo assumes the verifier of the JWT has already established that the RSA key that is being used to sign the JWT

>> this repo is not supported by google

### Supported Key Types

The following types are supported

* `RS256`
* `PS256`
* `ES256`

against the TPM `OWNER` hierarchy

### Usage

Use this library to issue JWTs in a way compatible with golang-jwt library.  The difference is that the caller must initialize a low-level [go-tpm/tpm2.TPMHandle][https://pkg.go.dev/github.com/google/go-tpm@v0.9.0/tpm2#TPMHandle] object from [go-tpm](https://github.com/google/go-tpm) and pass that through with any optional authorized session:

```golang
import (
	"github.com/golang-jwt/jwt/v5"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// initialize the TPM
rwc, err := tpm2.OpenTPM(*tpmPath)
defer rwc.Close()
rwr := transport.FromReadWriter(rwc)

// get an existing tpm based keys persistent or handle
// pass that to this library along with any session authorization 
rpub, err := tpm2.ReadPublic{
	ObjectHandle: tpm2.TPMHandle(*persistentHandle),
}.Execute(rwr)

config := &tpmjwt.TPMConfig{
	TPMDevice: rwc,
	AuthHandle: &tpm2.AuthHandle{
		Handle: tpm2.TPMHandle(*persistentHandle),
		Name:   rpub.Name,
		Auth:   tpm2.PasswordAuth(nil),
	},
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

# ssh to VM, install tpm2_tools from source
sudo su -
apt-get update

apt -y install   autoconf-archive   libcmocka0   libcmocka-dev   procps  \
   iproute2   build-essential   git   pkg-config   gcc   libtool   automake \
     libssl-dev   uthash-dev   autoconf   doxygen  libcurl4-openssl-dev dbus-x11 libglib2.0-dev libjson-c-dev acl

cd
git clone https://github.com/tpm2-software/tpm2-tss.git
  cd tpm2-tss
  ./bootstrap
  ./configure --with-udevrulesdir=/etc/udev/rules.d
  make -j$(nproc)
  make install
  udevadm control --reload-rules && sudo udevadm trigger
  ldconfig

cd
git clone https://github.com/tpm2-software/tpm2-tools.git
  cd tpm2-tools
  ./bootstrap
  ./configure
  make check
  make install


wget https://go.dev/dl/go1.22.2.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

Once on the VM, create a key on TPM (if you already have an existing key on TPM, you can acquire a handle and pass that to the library). 

### Usage

For simplicity, the following generates and embeds keys into a persistent handle using [tpm2_tools](https://github.com/tpm2-software/tpm2-tools).  (You are free to use any system to provision a key)

#### RSA 

Create RSA key at handle `0x81008001`, RSA-PSS handle at `0x81008004`. 

```bash
## RSA - no password
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
	tpm2_flushcontext  -t
	tpm2_getcap  handles-transient
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008001
	tpm2_flushcontext  -t

## rsa-pss
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsapss:null -g sha256 -u key.pub -r key.priv -C primary.ctx  --format=pem --output=rsapss_public.pem
	tpm2_flushcontext  -t
	tpm2_getcap  handles-transient 
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008004
	tpm2_flushcontext  -t

## ecc
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx  --format=pem --output=ecc_public.pem
	tpm2_flushcontext  -t
	tpm2_getcap  handles-transient  
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008005    
	tpm2_flushcontext  -t	
```

Then run,

```bash
cd example/

## RS256
$ go run nopolicy/main.go --mode=rsa --persistentHandle=0x81008001 --tpm-path=/dev/tpm0

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
$ go run nopolicy/main.go --mode=rsapss --persistentHandle=0x81008004 --tpm-path=/dev/tpm0

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
$ go run nopolicy/main.go --mode=ecc --persistentHandle=0x81008005 --tpm-path=/dev/tpm0

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
```

### Session Encryption

If you want to enable [session encryption](https://github.com/salrashid123/tpm2/tree/master/tpm_encrypted_session), you need to supply an external key you know to be associated with a TPM (eg an Endorsement Key):

```golang
	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}
	createEKRsp, err := createEKCmd.Execute(rwr)

	encryptionPub, err := createEKRsp.OutPublic.Contents()

	rpub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(*persistentHandle),
	}.Execute(rwr)

	config := &tpmjwt.TPMConfig{
		TPMDevice: rwc,
		AuthHandle: &tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(*persistentHandle),
			Name:   rpub.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		EncryptionHandle: createEKRsp.ObjectHandle,
		EncryptionPub:    encryptionPub,
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
		NamedHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(*persistentHandle),
			Name:   rpub.Name,
		},
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
		NamedHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(*persistentHandle),
			Name:   rpub.Name,
		},
		AuthSession: p,
	}
```

If you want to set those up using tpm2_tools:

```bash
## RSA - password

    tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -p pass1 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsassa:null -g sha256 -P pass1 -p pass2 -u key.pub -r key.priv -C primary.ctx
	tpm2_flushcontext  -t
	tpm2_getcap  handles-transient
	tpm2_load -C primary.ctx -P pass1 -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008002
	tpm2_flushcontext  -t

## RSA - pcr

	tpm2_pcrread sha256:23
	tpm2_startauthsession -S session.dat
	tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
	tpm2_flushcontext session.dat
	tpm2_flushcontext  -t
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256  -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx  -L policy.dat
	tpm2_flushcontext  -t
	tpm2_getcap  handles-transient
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008003
	tpm2_flushcontext  -t

```

Then,

```bash
cd example/

## passwordAuth
$ go run policy_password/main.go --persistentHandle=0x81008002 --tpm-path=/dev/tpm0

## pcrAuth
$ go run policy_pcr/main.go --persistentHandle=0x81008003 --tpm-path=/dev/tpm0
```

For more information, see [TPM2 Policy](https://github.com/salrashid123/tpm2/tree/master/policy)

Note, you can also define your own 

```golang
// for pcr sessions
type MySession struct {
	rwr transport.TPM
	sel []tpm2.TPMSPCRSelection
}

func NewMySession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection) (MySession, error) {
	return MySession{rwr, sel}, nil
}

func (p MySession) GetSession() (auth tpm2.Session, err error) {
	sess, _, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, err
	}

	// defineyour poicy here
	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func (p MySession) Close() error {
	return nil
}
```


### Sign/Verify with GCP builtin AKCert

vTPMs usually have an EK certificate and template encoded into NV area here described from pg 13 of [TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r3.pdf)

```
2.2.1.4 Low Range
The Low Range is at NV Indices 0x01c00002 - 0x01c0000c.
0x01c00002 RSA 2048 EK Certificate
0x01c00003 RSA 2048 EK Nonce
0x01c00004 RSA 2048 EK Template
0x01c0000a ECC NIST P256 EK Certificate
0x01c0000b ECC NIST P256 EK Nonce
0x01c0000c ECC NIST P256 EK Template
```

To see this and read the EKCertificate, 

```bash
export TPM2_EK_NV_INDEX=0x1c00002
tpm2_nvreadpublic | sed -n -e "/""$TPM2_EK_NV_INDEX""/,\$p" | sed -e '/^[ \r\n\t]*$/,$d' | grep "size" | sed 's/.*size.*://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]$//'
## note the 1422 is just the size i saw on NV for the cert, yours will be different
tpm2_nvread -s 1422  -C o $TPM2_EK_NV_INDEX |  openssl x509 --inform DER -text -noout  -in -
```

Note GCE VMs encodes a default the Attestation Certificate into NV area here:

```golang
	// RSA 2048 AK.
	GceAKCertNVIndexRSA     uint32 = 0x01c10000
	GceAKTemplateNVIndexRSA uint32 = 0x01c10001
```

which you can read in directly:

```bash
$ tpm2_nvreadpublic 

0x1c10000:
  name: 000bc1dcc77bde4982d4817bcbe8418d49c1f24e3a017e79e1be9d25f6bc50c0f7c2
  hash algorithm:
    friendly: sha256
    value: 0xB
  attributes:
    friendly: ppwrite|writedefine|ppread|ownerread|authread|no_da|written|platformcreate
    value: 0x62072001
  size: 1516


export GceAKCertNVIndexRSA=0x01c10000
## >>>note the size for me was 1516
tpm2_nvread -s 1516  -C o $GceAKCertNVIndexRSA |  openssl x509 --inform DER -text -noout  -in -
```

To sign with the attestation key (which is available remotely via GCE APIs and even signed by GCE), just a handle...eg using go-tpm-tools client:

```golang
// attestation key that is signed by GCE
sessionKey, err := client.GceAttestationKeyRSA(rwc)
//sessionKey, err := client.AttestationKeyRSA(rwc)
```

### Usign Simulator

If you down't want to run the tests on a real TPM, you can opt to use `swtpm` if its installed:

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

## run any TPM command
export TPM2TOOLS_TCTI="swtpm:port=2321"
tpm2_pcrread sha256:23
```

---

also see

- [Sign, Verify and decode using Google Cloud vTPM Endorsement and Attestation Key and Certificate](https://github.com/salrashid123/gcp-vtpm-ek-ak)
- [Sign with AK saved to NV (gce only)](https://github.com/salrashid123/tpm2/tree/master/ak_sign_nv)
- [go-tpm-tools.client.GceAttestationKeyRSA()](https://pkg.go.dev/github.com/google/go-tpm-tools/client#GceAttestationKeyRSA)

