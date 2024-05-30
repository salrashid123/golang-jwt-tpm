package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"time"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
)

/*
Load a key using https://github.com/Foxboron/go-tpm-keyfiles

$ go run go_keyfile_compat/main.go

2024/05/30 11:20:36 ======= Init  ========
2024/05/30 11:20:36 ======= createPrimary ========
2024/05/30 11:20:36 ======= create key  ========
2024/05/30 11:20:36 ======= writing key to file ========
2024/05/30 11:20:36 rsa Key PEM:
-----BEGIN TSS2 PRIVATE KEY-----
MIICEAYGZ4EFCgEDAgUAgAAAAASCARoBGAABAAsABAByAAAAEAAUAAsIAAAAAAAB
ANXwPYXZ6NmYih5TP8JOG+d9iLQ+Bq87Ev8tTGwUBSeMARYbjZ2Kxhd6QlgPisp7
rGrYEiSgFC3r4E9D27BnXkg+KOw6tn1l2m5+JPY7FqKYbqnaTTdWjDsnmHXBZGMZ
bo5eA7lSgZC9c6RuANn0iSQPaw9cpaLCxMOAG+yH3LzUb+c+PkHug8ww5diduQwr
dVB8bw4JQIICN3XoRXR8QRM785X+GEK7Qnk+/4aqcGzeP6rxC1mNuncj20V75JQi
cgz4++w0rQeakSjXCWL0LmgywRKJeXl2R0HgidO13piYQ9JM4cUt28mDPcly+o3E
culu9QS3Dd/MjpbYB00qQHcEgeAA3gAgJA3wcnk0NEcmAvKOCnSMmzy1acILMBR+
Oq5bsv842pgAEDwoSveyh3N1nytSQDSuItEbmMfKCzQsHYrRe2mzwONt/AvTjKc2
wQPLgR0wf2wz+yLyDA6kQ4KTvIOHxk7USzwk0tFZWvEDZi05viLsMwaGZ2yR4aYO
rPC0FO40oAAzQkuL+3/1ZdRPRQR4iIZB3VvKhU/bBFsHMwfUoZZMz7/YLrgsNeJH
XBjB1HtTp6keeCm3ljuVRUkSvyXFSMH0atvowRMLdFZ0TSO3SvFUTBDOTfMSWke6
0HWcbw==
-----END TSS2 PRIVATE KEY-----

2024/05/30 11:20:36 ======= reading key from file ========
2024/05/30 11:20:36 primaryKey Name AAvaZWBJngiVUFq6Dg/Q7uBxAK3INE3G/GOsnm7v0TGujQ==
2024/05/30 11:20:36      Signing PEM
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1fA9hdno2ZiKHlM/wk4b
532ItD4GrzsS/y1MbBQFJ4wBFhuNnYrGF3pCWA+KynusatgSJKAULevgT0PbsGde
SD4o7Dq2fWXabn4k9jsWophuqdpNN1aMOyeYdcFkYxlujl4DuVKBkL1zpG4A2fSJ
JA9rD1ylosLEw4Ab7IfcvNRv5z4+Qe6DzDDl2J25DCt1UHxvDglAggI3dehFdHxB
Ezvzlf4YQrtCeT7/hqpwbN4/qvELWY26dyPbRXvklCJyDPj77DStB5qRKNcJYvQu
aDLBEol5eXZHQeCJ07XemJhD0kzhxS3byYM9yXL6jcRy6W71BLcN38yOltgHTSpA
dwIDAQAB
-----END PUBLIC KEY-----
TOKEN: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzE3MDgyNDk2fQ.Gyb8YIeQsbbl5mFVn55dO-J26HuwM1JK94RdrOEafySI7YJzfOkSeSAaSHvNR9aPiHh--nx3oMYpxPwPR161mKBF-w9DETqHn6lUqFSYzEk7tut-E1LrohrACkhSS_VbJuUw9S57imYMqzI9BTKm-FFG1mYBktWI0UWxC7e5wGaajS_cJc7fRx-5Ni-lDyBxYL1Az1ApIg9bwkEJxG7fLSI2_nsO9Unzd1mpRZ2nBUMjaK2aoG8vZMhHOK80R46VEeBq1ZT2xoaXiNZshBRf2mIptLpfSNVjT1gDCWdKVtIaBHevTpzmQLflQJVdSNKinCst-7N_QzF2UEPRBGx7GQ
2024/05/30 11:20:36      verified with TPM PublicKey
2024/05/30 11:20:36      verified with exported PubicKey
*/
var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	out     = flag.String("out", "private.pem", "privateKey File")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {

	flag.Parse()
	ctx := context.Background()

	log.Printf("======= Init  ========")

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	log.Printf("======= createPrimary ========")

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// rsa

	log.Printf("======= create key  ========")

	rsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create rsa %v", err)
	}

	// write the key to file
	log.Printf("======= writing key to file ========")

	//tkf, err := keyfile.NewLoadableKey(rsaKeyResponse.OutPublic, rsaKeyResponse.OutPrivate, tpm2.TPMHandle(*persistenthandle), false)
	tkf, err := keyfile.NewLoadableKey(rsaKeyResponse.OutPublic, rsaKeyResponse.OutPrivate, primaryKey.ObjectHandle, false)
	if err != nil {
		log.Fatalf("failed to create KeyFile: %v", err)
	}

	b := new(bytes.Buffer)

	err = keyfile.Encode(b, tkf)
	if err != nil {
		log.Fatalf("failed to encode Key: %v", err)
	}

	log.Printf("rsa Key PEM: \n%s\n", b)

	err = os.WriteFile(*out, b.Bytes(), 0644)
	if err != nil {
		log.Fatalf("failed to write private key to file %v", err)
	}

	log.Printf("======= reading key from file ========")
	c, err := os.ReadFile(*out)
	if err != nil {
		log.Fatalf("error reading private keyfile: %v", err)
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		log.Fatalf("failed decoding key: %v", err)
	}

	regenRSAKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load rsa key: %v", err)
	}

	flush := tpm2.FlushContext{
		FlushHandle: primaryKey.ObjectHandle,
	}
	_, err = flush.Execute(rwr)
	if err != nil {
		log.Fatalf("can't close primary  %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: regenRSAKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	var token *jwt.Token

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	log.Printf("primaryKey Name %s\n", base64.StdEncoding.EncodeToString(primaryKey.Name.Buffer))

	pub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(regenRSAKey.ObjectHandle),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing tpm2.ReadPublic %v", err)
	}

	outPub, err := pub.OutPublic.Contents()
	if err != nil {
		log.Fatalf("error reading public contexts %v", err)
	}

	var pubKey crypto.PublicKey

	tpmjwt.SigningMethodTPMRS256.Override()
	token = jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

	rsaDetail, err := outPub.Parameters.RSADetail()
	if err != nil {
		log.Fatalf("error reading rsa public %v", err)
	}
	rsaUnique, err := outPub.Unique.RSA()
	if err != nil {
		log.Fatalf("error reading rsa unique %v", err)
	}

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		log.Fatalf("Failed to get rsa public key: %v", err)
	}

	pubKey = rsaPub

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
		Handle:    tpm2.TPMHandle(regenRSAKey.ObjectHandle),
		Session:   tpm2.PasswordAuth(nil),
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

	v, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return pubKeyr, nil
	})
	if err != nil {
		log.Fatalf("Error parsing token %v", err)
	}
	if v.Valid {
		log.Println("     verified with exported PubicKey")
	}
}
