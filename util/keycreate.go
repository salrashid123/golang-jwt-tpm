// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"crypto/sha256"
	"crypto/x509"
	"flag"

	"log"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lestrrat-go/jwx/jwk"
)

const ()

var ()

var (
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	keyAlg           = flag.String("keyAlg", "RSA", "Key Algorithm")
	publicKeyFile    = flag.String("publicKeyFile", "key.pem", "PEM File to write the public key")
	persistentHandle = flag.Uint("persistentHandle", 0x81008001, "Handle value")
	flushHandles     = flag.Bool("flushHandles", false, "FlushTPM Hanldles")
	evict            = flag.Bool("evict", false, "Evict prior handle")
	handleNames      = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
		"none":      {},
	}
	// using attestation key
	keyParametersRSA = client.AKTemplateRSA()
	keyParametersECC = client.AKTemplateECC()

	// using unrestricted key
	keyParametersImported = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}

	keyParametersCreatedRSA = tpm2.Public{
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

	keyParametersCreatedECC = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
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

	var k *client.Key

	if *keyAlg == "RSA" {
		k, err = client.NewKey(rwc, tpm2.HandleOwner, keyParametersRSA)
	} else if *keyAlg == "ECC" {
		k, err = client.NewKey(rwc, tpm2.HandleOwner, keyParametersECC)
	} else {
		log.Fatalf("unknown key parameter handles: %s", *keyAlg)
	}
	if err != nil {
		log.Fatalf("can't create SRK %q: %v", *tpmPath, err)
	}

	log.Printf("     key Name: \n%s", hex.EncodeToString(k.Name().Digest.Value))

	kh := k.Handle()
	log.Printf("======= PersistHandle (k) ========")
	pHandle := tpmutil.Handle(*persistentHandle)
	// if you want to evict an existing
	if *evict {
		err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, pHandle, pHandle)
		if err != nil {
			glog.Fatalf("     Unable evict persistentHandle: %v ", err)
		}
	}

	err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, kh, pHandle)
	if err != nil {
		glog.Fatalf("     Unable to set persistentHandle: %v", err)
	}
	defer tpm2.FlushContext(rwc, kh)

	kPublicKey, _, _, err := tpm2.ReadPublic(rwc, kh)
	if err != nil {
		log.Fatalf("Error tpmEkPub.Key() failed: %s", err)
	}

	ap, err := kPublicKey.Key()
	if err != nil {
		log.Fatalf("reading Key() failed: %s", err)
	}
	akBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		log.Fatalf("Unable to convert ekpub: %v", err)
	}

	rakPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	log.Printf("     PublicKey: \n%v", string(rakPubPEM))

	err = os.WriteFile(*publicKeyFile, rakPubPEM, 0644)
	if err != nil {
		log.Fatalf("Could not write file %v", err)
	}
	log.Printf("Public Key written to: %s", *publicKeyFile)

	der, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		log.Fatalf("keycreate: error converting public key: %v", err)
	}
	hasher := sha256.New()
	hasher.Write(der)
	kid := base64.RawStdEncoding.EncodeToString(hasher.Sum(nil))

	jkey, err := jwk.New(ap)
	if err != nil {
		log.Fatalf("failed to create symmetric key: %s\n", err)
	}
	jkey.Set(jwk.KeyIDKey, kid)

	buf, err := json.MarshalIndent(jkey, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal key into JSON: %s\n", err)
		return
	}
	fmt.Printf("JWK Format:\n%s\n", buf)

}
