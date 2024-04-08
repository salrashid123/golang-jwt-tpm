package main

import (
	"context"
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
tpm2_pcrread sha256:23
tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
tpm2_flushcontext session.dat
tpm2_createprimary -C o -c primary2.ctx
tpm2_create -G rsa2048:rsassa:null -g sha256 -u rsa2.pub -r rsa2.priv -C primary2.ctx  -L policy.dat
tpm2_load -C primary2.ctx -u rsa2.pub -r rsa2.priv -c rsa2.ctx
tpm2_evictcontrol -C o -c rsa2.ctx 0x81008004
*/

var (
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81008004, "Handle value")
	pcr              = flag.Int("pcr", 23, "PCR Bound value")
)

func main() {

	flag.Parse()
	ctx := context.Background()

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

	tpmjwt.SigningMethodTPMRS256.Override()
	token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

	s, err := client.NewPCRSession(rwc, tpm2.PCRSelection{tpm2.AlgSHA256, []int{*pcr}})
	if err != nil {
		log.Fatalf("Unable to initialize tpmJWT: %v", err)
	}
	defer s.Close()
	sessionKey, err := client.LoadCachedKey(rwc, tpmutil.Handle(*persistentHandle), s)
	if err != nil {
		log.Fatalf("Unable to Load Key: %v", err)
	}
	defer sessionKey.Close()
	sessionConfig := &tpmjwt.TPMConfig{
		TPMDevice: rwc,
		Key:       sessionKey,
	}
	sessionKeyctx, err := tpmjwt.NewTPMContext(ctx, sessionConfig)
	if err != nil {
		log.Fatalf("Unable to initialize tpmJWT: %v", err)
	}

	sessionTokenString, err := token.SignedString(sessionKeyctx)
	if err != nil {
		log.Fatalf("Error signing %v", err)
	}
	fmt.Printf("TOKEN: %s\n", sessionTokenString)

	sessionKeyFunc, err := tpmjwt.TPMVerfiyKeyfunc(ctx, sessionConfig)
	if err != nil {
		log.Fatalf("could not get keyFunc: %v", err)
	}

	sessionVtoken, err := jwt.Parse(sessionTokenString, sessionKeyFunc)
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if sessionVtoken.Valid {
		log.Println("     verified with TPM PublicKey")
	}

}
