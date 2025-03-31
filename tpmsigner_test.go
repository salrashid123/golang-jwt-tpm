package tpmjwt

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

var (
	rsaTemplate = tpm2.TPMTPublic{
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

	rsaTemplateNoUserWithAuth = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        false,
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

	rsaPSSTemplate = tpm2.TPMTPublic{
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
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSigSchemeRSAPSS{
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

	eccTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
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
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 32),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 32),
				},
			},
		),
	}
)

func TestTPMRSA(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		Handle:    rsaKeyResponse.ObjectHandle,
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

func TestTPMRSAAK(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	require.NoError(t, err)
	defer cleanup1()

	_, err = tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		NonceTPM:      sess.NonceTPM(),
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	rt := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			SignEncrypt:         true,
			NoDA:                true,
		},
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
	}

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   sess,
		},
		InPublic: tpm2.New2BTemplate(&rt),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		Handle:    rsaKeyResponse.ObjectHandle,
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

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		Handle:    rsaKeyResponse.ObjectHandle,
	}
	keyctx, err := NewTPMContext(context.Background(), config)
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	rsaKeyResponse2, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	newConfig := &TPMConfig{
		TPMDevice: tpmDevice,
		Handle:    rsaKeyResponse2.ObjectHandle,
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

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()
	SigningMethodTPMRS256.Override()

	zeroBytes := make([]byte, 2048)

	tests := []struct {
		name   string
		issuer string
	}{
		{"small_claim", "test"},
		{"large_claim", string(zeroBytes)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := &jwt.RegisteredClaims{
				ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
				Issuer:    tc.issuer,
			}
			token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

			config := &TPMConfig{
				TPMDevice: tpmDevice,
				Handle:    rsaKeyResponse.ObjectHandle,
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
			require.Equal(t, tc.issuer, tokenIssuer)
		})
	}
}

func TestTPMRSAPSS(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaPSSTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	SigningMethodTPMPS256.Override()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}
	token := jwt.NewWithClaims(SigningMethodTPMPS256, claims)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		Handle:    rsaKeyResponse.ObjectHandle,
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

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	eccKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&eccTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: eccKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	SigningMethodTPMES256.Override()

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}
	token := jwt.NewWithClaims(SigningMethodTPMES256, claims)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		Handle:    eccKeyResponse.ObjectHandle,
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

func TestTPMPasswordPolicy(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	keyPassword := []byte("pass1")

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: keyPassword,
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	p, err := NewPasswordSession(rwr, []byte(keyPassword))
	require.NoError(t, err)

	config := &TPMConfig{
		TPMDevice:   tpmDevice,
		Handle:      rsaKeyResponse.ObjectHandle,
		AuthSession: p,
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

func TestTPMPasswordNoPolicyFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	keyPassword := []byte("pass1")

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: keyPassword,
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		Handle:    rsaKeyResponse.ObjectHandle,
	}

	keyctx, err := NewTPMContext(context.Background(), config)
	require.NoError(t, err)

	_, err = token.SignedString(keyctx)
	require.Error(t, err)

}

func TestTPMPasswordPolicyWrongPasswordFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	keyPassword := []byte("pass1")
	wrongPassword := []byte("wrongpass1")
	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: keyPassword,
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	p, err := NewPasswordSession(rwr, []byte(wrongPassword))
	require.NoError(t, err)

	config := &TPMConfig{
		TPMDevice:   tpmDevice,
		Handle:      rsaKeyResponse.ObjectHandle,
		AuthSession: p,
	}

	keyctx, err := NewTPMContext(context.Background(), config)
	require.NoError(t, err)

	_, err = token.SignedString(keyctx)
	require.Error(t, err)
}

func TestTPMPolicyPCR(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pcr := 23

	sess, cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	require.NoError(t, err)
	defer cleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr)),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = tpm2.FlushContext{FlushHandle: sess.Handle()}.Execute(rwr)
	require.NoError(t, err)

	rsaTemplateNoUserWithAuth.AuthPolicy = tpm2.TPM2BDigest{
		Buffer: pgd.PolicyDigest.Buffer,
	}
	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplateNoUserWithAuth),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	p, err := NewPCRSession(rwr, []tpm2.TPMSPCRSelection{
		{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr)),
		},
	})
	config := &TPMConfig{
		TPMDevice:   tpmDevice,
		Handle:      rsaKeyResponse.ObjectHandle,
		AuthSession: p,
	}

	keyctx, err := NewTPMContext(context.Background(), config)
	require.NoError(t, err)

	_, err = token.SignedString(keyctx)
	require.NoError(t, err)
}

func TestTPMPolicyPCRExtendFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pcr := 23

	sess, cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	require.NoError(t, err)
	defer cleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr)),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = tpm2.FlushContext{FlushHandle: sess.Handle()}.Execute(rwr)
	require.NoError(t, err)

	rsaTemplateNoUserWithAuth.AuthPolicy = tpm2.TPM2BDigest{
		Buffer: pgd.PolicyDigest.Buffer,
	}
	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplateNoUserWithAuth),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	/// sign
	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	p, err := NewPCRSession(rwr, []tpm2.TPMSPCRSelection{
		{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr)),
		},
	})
	require.NoError(t, err)
	config := &TPMConfig{
		TPMDevice:   tpmDevice,
		Handle:      rsaKeyResponse.ObjectHandle,
		AuthSession: p,
	}
	keyctx, err := NewTPMContext(context.Background(), config)
	require.NoError(t, err)

	/// extend pcr value

	pcrReadRsp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr)),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(uint(pcr)),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  pcrReadRsp.PCRValues.Digests[0].Buffer,
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	// sign again

	_, err = token.SignedString(keyctx)
	require.Error(t, err)
}

func TestTPMPolicyPCRNoSessionFail(t *testing.T) {
	tpmDevice, err := simulator.GetWithFixedSeedInsecure(123456789)
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pcr := 23

	sess, cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	require.NoError(t, err)
	defer cleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr)),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = tpm2.FlushContext{FlushHandle: sess.Handle()}.Execute(rwr)
	require.NoError(t, err)

	rsaTemplateNoUserWithAuth.AuthPolicy = tpm2.TPM2BDigest{
		Buffer: pgd.PolicyDigest.Buffer,
	}
	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplateNoUserWithAuth),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// **************

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		Handle:    rsaKeyResponse.ObjectHandle,
	}

	keyctx, err := NewTPMContext(context.Background(), config)
	require.NoError(t, err)

	_, err = token.SignedString(keyctx)
	require.Error(t, err)
}

func TestTPMSessionEncryption(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}
	createEKRsp, err := createEKCmd.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKRsp.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	config := &TPMConfig{
		TPMDevice:        tpmDevice,
		Handle:           rsaKeyResponse.ObjectHandle,
		EncryptionHandle: createEKRsp.ObjectHandle,
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

func TestTPMRSANameHandle(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	SigningMethodTPMRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTPMRS256, claims)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: rsaKeyResponse.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	config := &TPMConfig{
		TPMDevice: tpmDevice,
		NamedHandle: tpm2.NamedHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   pub.Name,
		},
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
