package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
)

/*
## RSA
	tpm2_createprimary -C e -c primary.ctx
	tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008001

## ECC
	tpm2_createprimary -C e -c primary.ctx
	tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008002
*/

var (
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81008001, "Handle value")
	template         = flag.String("template", "akrsa", "Template to use, one of ak|cached")
)

func main() {

	flag.Parse()
	ctx := context.Background()

	log.Printf("======= Init  ========")

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	var token *jwt.Token

	k, err := client.LoadCachedKey(rwc, tpmutil.Handle(*persistentHandle), nil)
	if err != nil {
		log.Printf("ERROR:  could not initialize Key: %v", err)
		return
	}
	defer k.Close()

	var pubKey crypto.PublicKey
	switch k.PublicKey().(type) {
	case *rsa.PublicKey:
		tpmjwt.SigningMethodTPMRS256.Override()
		token = jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

		pubKey = k.PublicKey().(*rsa.PublicKey)
	case *ecdsa.PublicKey:
		tpmjwt.SigningMethodTPMES256.Override()
		token = jwt.NewWithClaims(tpmjwt.SigningMethodTPMES256, claims)

		pubKey = k.PublicKey().(*ecdsa.PublicKey)
	default:
		log.Printf("ERROR:  unsupported key type: %v", k.PublicKey())
		return
	}

	akBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Printf("ERROR:  could not get MarshalPKIXPublicKey: %v", err)
		return
	}

	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	log.Printf("     Signing PEM \n%s", string(akPubPEM))

	config := &tpmjwt.TPMConfig{
		TPMDevice: rwc,
		Key:       k,
	}

	keyctx, err := tpmjwt.NewTPMContext(ctx, config)
	if err != nil {
		log.Fatalf("Unable to initialize tpmJWT: %v", err)
	}

	// optionally set a keyID
	//token.Header["kid"] = config.GetKeyID()

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
	pubKeyr := config.GetPublicKey()

	v, err := jwt.Parse(vtoken.Raw, func(token *jwt.Token) (interface{}, error) {
		return pubKeyr, nil
	})
	if err != nil {
		log.Fatalf("Error parsing token %v", err)
	}
	if v.Valid {
		log.Println("     verified with exported PubicKey")
	}
}
