package tpmjwt

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/require"
)

// copied from https://github.com/google/go-tpm-tools/blob/v0.4.0/client/signer_test.go#L18-L24
func templateRSASSA(hash tpm2.Algorithm) tpm2.Public {
	template := client.AKTemplateRSA()
	// Can't sign arbitrary data if restricted.
	template.Attributes &= ^tpm2.FlagRestricted
	template.RSAParameters.Sign.Hash = hash
	return template
}

func templateRSAPSS(hash tpm2.Algorithm) tpm2.Public {
	template := client.AKTemplateRSA()
	// Can't sign arbitrary data if restricted.
	template.Attributes &= ^tpm2.FlagRestricted
	template.RSAParameters.Sign.Hash = hash
	template.RSAParameters.Sign.Alg = tpm2.AlgRSAPSS
	return template
}

func templateECC(hash tpm2.Algorithm) tpm2.Public {
	template := client.AKTemplateECC()
	// Can't sign arbitrary data if restricted.
	template.Attributes &= ^tpm2.FlagRestricted
	template.ECCParameters.Sign.Hash = hash
	return template
}

func TestTPMPublic(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, client.SRKTemplateRSA())
	require.NoError(t, err)
	defer createdKey.Close()

	k, err := client.LoadCachedKey(tpmDevice, createdKey.Handle(), nil)
	require.NoError(t, err)
	defer k.Close()

	k.PublicKey()
	SigningMethodTPMRS256.Override()

	pubKey, ok := k.PublicKey().(*rsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, pubKey, k.PublicKey())
	require.Equal(t, 2048, pubKey.Size()*8)
}

func TestTPMRSA(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, templateRSASSA(tpm2.AlgSHA256))
	require.NoError(t, err)
	defer createdKey.Close()

	k, err := client.LoadCachedKey(tpmDevice, createdKey.Handle(), nil)
	require.NoError(t, err)
	defer k.Close()

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		Key:       k,
	}
	keyctx, err := NewTPMContext(context.Background(), config)
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := TPMVerfiyKeyfunc(context.Background(), config)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}

func TestTPMRSAFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, templateRSASSA(tpm2.AlgSHA256))
	require.NoError(t, err)
	defer createdKey.Close()

	k, err := client.LoadCachedKey(tpmDevice, createdKey.Handle(), nil)
	require.NoError(t, err)
	defer k.Close()

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		Key:       k,
	}
	keyctx, err := NewTPMContext(context.Background(), config)
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	newcreatedKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, templateRSASSA(tpm2.AlgSHA256))
	require.NoError(t, err)
	defer newcreatedKey.Close()

	newk, err := client.LoadCachedKey(tpmDevice, newcreatedKey.Handle(), nil)
	require.NoError(t, err)
	defer k.Close()

	newConfig := &TPMConfig{
		TPMDevice: tpmDevice,
		Key:       newk,
	}

	newkeyFunc, err := TPMVerfiyKeyfunc(context.Background(), newConfig)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, newkeyFunc)
	require.Error(t, err)

	require.False(t, vtoken.Valid)
}

func TestTPMClaim(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, templateRSASSA(tpm2.AlgSHA256))
	require.NoError(t, err)
	defer createdKey.Close()

	k, err := client.LoadCachedKey(tpmDevice, createdKey.Handle(), nil)
	require.NoError(t, err)
	defer k.Close()

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		Key:       k,
	}
	keyctx, err := NewTPMContext(context.Background(), config)
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := TPMVerfiyKeyfunc(context.Background(), config)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	tokenIssuer, err := vtoken.Claims.GetIssuer()
	require.NoError(t, err)
	require.Equal(t, issuer, tokenIssuer)
}

func TestTPMRSAPSS(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, templateRSAPSS(tpm2.AlgSHA256))
	require.NoError(t, err)
	defer createdKey.Close()

	k, err := client.LoadCachedKey(tpmDevice, createdKey.Handle(), nil)
	require.NoError(t, err)
	defer k.Close()

	SigningMethodTPMPS256.Override()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}
	token := jwt.NewWithClaims(SigningMethodTPMPS256, claims)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		Key:       k,
	}
	keyctx, err := NewTPMContext(context.Background(), config)
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := TPMVerfiyKeyfunc(context.Background(), config)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}

func TestTPMECC(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, templateECC(tpm2.AlgSHA256))
	require.NoError(t, err)
	defer createdKey.Close()

	k, err := client.LoadCachedKey(tpmDevice, createdKey.Handle(), nil)
	require.NoError(t, err)
	defer k.Close()

	SigningMethodTPMES256.Override()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}
	token := jwt.NewWithClaims(SigningMethodTPMES256, claims)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		Key:       k,
	}
	keyctx, err := NewTPMContext(context.Background(), config)
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := TPMVerfiyKeyfunc(context.Background(), config)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}

func TestTPMPolicy(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	s, err := client.NewPCRSession(tpmDevice, tpm2.PCRSelection{tpm2.AlgSHA256, []int{0}})
	require.NoError(t, err)
	ac, err := s.Auth()
	require.NoError(t, err)

	sessionTemplate := templateRSASSA(tpm2.AlgSHA256)
	sessionTemplate.AuthPolicy = ac.Auth

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, sessionTemplate)
	require.NoError(t, err)
	defer createdKey.Close()

	k, err := client.LoadCachedKey(tpmDevice, createdKey.Handle(), nil)
	require.NoError(t, err)
	defer k.Close()

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		Key:       k,
	}
	keyctx, err := NewTPMContext(context.Background(), config)
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := TPMVerfiyKeyfunc(context.Background(), config)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}

func TestTPMSignPolicyFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	pcr := 23

	s, err := client.NewPCRSession(tpmDevice, tpm2.PCRSelection{tpm2.AlgSHA256, []int{pcr}})
	require.NoError(t, err)
	ac, err := s.Auth()
	require.NoError(t, err)

	sessionTemplate := templateRSASSA(tpm2.AlgSHA256)
	sessionTemplate.AuthPolicy = ac.Auth

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, sessionTemplate)
	require.NoError(t, err)
	defer createdKey.Close()

	pcrval, err := tpm2.ReadPCR(tpmDevice, pcr, tpm2.AlgSHA256)
	require.NoError(t, err)

	pcrToExtend := tpmutil.Handle(pcr)

	err = tpm2.PCRExtend(tpmDevice, pcrToExtend, tpm2.AlgSHA256, pcrval, "")
	require.NoError(t, err)

	ps, err := client.NewPCRSession(tpmDevice, tpm2.PCRSelection{tpm2.AlgSHA256, []int{pcr}})
	require.NoError(t, err)

	loadedKey, err := client.LoadCachedKey(tpmDevice, createdKey.Handle(), ps)
	require.NoError(t, err)
	defer loadedKey.Close()

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		Key:       loadedKey,
	}
	keyctx, err := NewTPMContext(context.Background(), config)
	require.NoError(t, err)

	_, err = token.SignedString(keyctx)
	require.Error(t, err)

}
