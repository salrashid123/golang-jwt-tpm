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
	"io/ioutil"

	"crypto/sha256"
	"crypto/x509"
	"flag"

	"log"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/lestrrat-go/jwx/jwk"
)

const ()

var (
	cfg = &certGenConfig{}
)

type certGenConfig struct {
	flCN       string
	flFileName string
	flSNI      string
}

var (
	tpmPath       = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	publicKeyFile = flag.String("publicKeyFile", "key.pem", "PEM File to write the public key")
	// pemCSRFile = flag.String("pemCSRFile", "key.csr", "CSR File to write to")
	keyFile = flag.String("keyFile", "key.bin", "TPM KeyFile")

	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
		"none":      {},
	}
	// using attestation key
	keyParameters = client.AKTemplateRSA()

	// using unrestricted key
	// keyParameters = tpm2.Public{
	// 	Type:    tpm2.AlgRSA,
	// 	NameAlg: tpm2.AlgSHA256,
	// 	Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
	// 		tpm2.FlagUserWithAuth | tpm2.FlagSign,
	// 	AuthPolicy: []byte{},
	// 	RSAParameters: &tpm2.RSAParams{
	// 		Sign: &tpm2.SigScheme{
	// 			Alg:  tpm2.AlgRSASSA,
	// 			Hash: tpm2.AlgSHA256,
	// 		},
	// 		KeyBits: 2048,
	// 	},
	// }
)

func main() {

	flag.Parse()
	log.Printf("======= Init  ========")

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("%v\ncan't close TPM %q: %v", tpmPath, err)
		}
	}()

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

	k, err := client.NewKey(rwc, tpm2.HandleOwner, keyParameters)
	if err != nil {
		log.Fatalf("can't create SRK %q: %v", tpmPath, err)
	}

	log.Printf("     key Name: \n%s", hex.EncodeToString(k.Name().Digest.Value))

	kh := k.Handle()
	log.Printf("======= ContextSave (k) ========")
	khBytes, err := tpm2.ContextSave(rwc, kh)
	if err != nil {
		log.Fatalf("ContextSave failed for ekh: %v", err)
	}

	err = ioutil.WriteFile(*keyFile, khBytes, 0644)
	if err != nil {
		log.Fatalf("ContextSave failed for ekh: %v", err)
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

	err = ioutil.WriteFile(*publicKeyFile, rakPubPEM, 0644)
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

	// glog.V(2).Infof("======= ContextLoad (k) ========")
	// khBytes, err = ioutil.ReadFile(*keyFile)
	// if err != nil {
	// 	log.Fatalf("ContextLoad failed for ekh: %v", err)
	// }
	// kh, err = tpm2.ContextLoad(rwc, khBytes)
	// if err != nil {
	// 	log.Fatalf("ContextLoad failed for kh: %v", err)
	// }
	// kk, err := client.NewCachedKey(rwc, tpm2.HandleOwner, unrestrictedKeyParams, kh)
	// s, err := kk.GetSigner()
	// if err != nil {
	// 	log.Fatalf("can't getSigner %q: %v", tpmPath, err)
	// }

	// log.Printf("Creating CSR")

	// var csrtemplate = x509.CertificateRequest{
	// 	Subject: pkix.Name{
	// 		Organization:       []string{"Acme Co"},
	// 		OrganizationalUnit: []string{"Enterprise"},
	// 		Locality:           []string{"Mountain View"},
	// 		Province:           []string{"California"},
	// 		Country:            []string{"US"},
	// 		CommonName:         *san,
	// 	},
	// 	DNSNames:           []string{*san},
	// 	SignatureAlgorithm: x509.SHA256WithRSA,
	// }

	// csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, s)
	// if err != nil {
	// 	log.Fatalf("Failed to create CSR: %s", err)
	// }

	// pemdata := pem.EncodeToMemory(
	// 	&pem.Block{
	// 		Type:  "CERTIFICATE REQUEST",
	// 		Bytes: csrBytes,
	// 	},
	// )
	// log.Printf("CSR \b%s\n", string(pemdata))

	// err = ioutil.WriteFile(*pemCSRFile, pemdata, 0644)
	// if err != nil {
	// 	log.Fatalf("Could not write file %v", err)
	// }
	// log.Printf("CSR written to: %s", *pemCSRFile)

}
