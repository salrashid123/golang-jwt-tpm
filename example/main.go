package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81008001, "Handle value")
	keyAlg           = flag.String("keyAlg", "RSA", "Key Algorithm")
	template         = flag.String("template", "akrsa", "Template to use, one of ak|cached")
	flushHandles     = flag.Bool("flushHandles", false, "FlushTPM Hanldles")
	handleNames      = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
		"none":      {},
	}

	rsaKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}

	eccKeyParams = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		ECCParameters: &tpm2.ECCParams{
			Sign:    &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256},
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: make([]byte, 32),
				YRaw: make([]byte, 32),
			},
		},
	}
)

func main() {

	flag.Parse()
	ctx := context.Background()

	log.Printf("======= Init  ========")

	if !(*keyAlg == "RSA" || *keyAlg == "ECC") {
		log.Fatalf("keyAlg must be either RSA or ECC")
	}

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	if *flushHandles {
		totalHandles := 0
		for _, handleType := range handleNames["all"] {
			handles, err := client.Handles(rwc, handleType)
			if err != nil {
				log.Fatalf("getting handles: %v", err)
			}
			for _, handle := range handles {
				if err = tpm2.FlushContext(rwc, handle); err != nil {
					log.Fatalf("flushing handle 0x%x: %v", handle, err)
				}
				log.Printf("Handle 0x%x flushed\n", handle)
				totalHandles++
			}
		}
		log.Printf("%d handles flushed\n", totalHandles)
	}

	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		Issuer:    "test",
	}

	var token *jwt.Token

	if *keyAlg == "RSA" {
		tpmjwt.SigningMethodTPMRS256.Override()
		token = jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)
	} else if *keyAlg == "ECC" {
		tpmjwt.SigningMethodTPMES256.Override()
		token = jwt.NewWithClaims(tpmjwt.SigningMethodTPMES256, claims)
	} else {
		log.Printf("Unknown Key Type %s", *keyAlg)
	}
	log.Printf("     Load SigningKey from template %s ", *template)

	var k *client.Key
	switch {
	case *template == "akrsa":
		k, err = client.AttestationKeyRSA(rwc)
		//k, err = client.GceAttestationKeyRSA(rwc)
	case *template == "akecc":
		k, err = client.AttestationKeyECC(rwc)
		//k, err = client.GceAKCertNVIndexECC(rwc)
	case *template == "cached":
		if *persistentHandle == 0 {
			log.Printf("error:  persistentHandle must be specified for cached keys")
			return
		}
		// k, err = client.LoadCachedKey(rwc, tpmutil.Handle(*persistentHandle), client.EKSession{})
		k, err = client.LoadCachedKey(rwc, tpmutil.Handle(*persistentHandle), nil)
	case *template == "created":
		if *persistentHandle == 0 {
			log.Printf("error:  persistentHandle must be specified for created keys")
			return
		}
		if *keyAlg == "RSA" {
			k, err = client.NewCachedKey(rwc, tpm2.HandleOwner, rsaKeyParams, tpmutil.Handle(*persistentHandle))
		} else if *keyAlg == "ECC" {
			k, err = client.NewCachedKey(rwc, tpm2.HandleOwner, eccKeyParams, tpmutil.Handle(*persistentHandle))
		}
	default:
		log.Printf("template type must be one of akrsa|akecc|imported|created")
		return
	}
	if err != nil {
		log.Printf("ERROR:  could not initialize Key: %v", err)
		return
	}

	var akBytes []byte

	if *keyAlg == "RSA" {
		pubKey := k.PublicKey().(*rsa.PublicKey)
		akBytes, err = x509.MarshalPKIXPublicKey(pubKey)
	} else if *keyAlg == "ECC" {
		pubKey := k.PublicKey().(*ecdsa.PublicKey)
		akBytes, err = x509.MarshalPKIXPublicKey(pubKey)
	}
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
