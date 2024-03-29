package tpmjwt

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	jwt "github.com/golang-jwt/jwt"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
)

// Much of this implementation is inspired templated form [gcp-jwt-go](https://github.com/someone1/gcp-jwt-go)

type TPMConfig struct {
	TPMDevice        io.ReadWriteCloser
	Key              *client.Key      // load a key from handle
	KeyID            string           // (optional) the TPM keyID (normally the key "Name")
	publicKeyFromTPM crypto.PublicKey // the public key as read from KeyHandleFile, KeyHandleNV
}

type tpmConfigKey struct{}

func (k *TPMConfig) GetKeyID() string {
	return k.KeyID
}

func (k *TPMConfig) GetPublicKey() crypto.PublicKey {
	return k.publicKeyFromTPM
}

var (
	SigningMethodTPMRS128 *SigningMethodTPM
	SigningMethodTPMRS256 *SigningMethodTPM
	errMissingConfig      = errors.New("tpmjwt: missing configuration in provided context")
	errMissingTPM         = errors.New("tpmjwt: TPM device not available")

	key client.Key
)

type SigningMethodTPM struct {
	alg      string
	override jwt.SigningMethod
	hasher   crypto.Hash
}

func NewTPMContext(parent context.Context, val *TPMConfig) (context.Context, error) {

	// first check if a TPM is even involved in the picture here since we can verify w/o a TPM
	if val.TPMDevice == nil || val.Key == nil {
		return nil, fmt.Errorf("tpmjwt: tpm device or key not set")
	}
	// TODO: check ECkey
	val.publicKeyFromTPM = val.Key.PublicKey()

	return context.WithValue(parent, tpmConfigKey{}, val), nil
}

// KMSFromContext extracts a KMSConfig from a context.Context
func TPMFromContext(ctx context.Context) (*TPMConfig, bool) {
	val, ok := ctx.Value(tpmConfigKey{}).(*TPMConfig)
	return val, ok
}

func init() {
	// RS256
	SigningMethodTPMRS256 = &SigningMethodTPM{
		"TPMRS256",
		jwt.SigningMethodRS256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodTPMRS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodTPMRS256
	})
}

// Alg will return the JWT header algorithm identifier this method is configured for.
func (s *SigningMethodTPM) Alg() string {
	return s.alg
}

// Override will override the default JWT implementation of the signing function this Cloud KMS type implements.
func (s *SigningMethodTPM) Override() {
	s.alg = s.override.Alg()
	jwt.RegisterSigningMethod(s.alg, func() jwt.SigningMethod {
		return s
	})
}

func (s *SigningMethodTPM) Hash() crypto.Hash {
	return s.hasher
}

func (s *SigningMethodTPM) Sign(signingString string, key interface{}) (string, error) {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return "", jwt.ErrInvalidKey
	}
	config, ok := TPMFromContext(ctx)
	if !ok {
		return "", errMissingConfig
	}

	// first make the TPM hash the data.  We need to do this incase the key is an attestation key
	//  (ie, a restricted key)
	digest, hashValidation, err := tpm2.Hash(config.TPMDevice, tpm2.AlgSHA256, []byte(signingString), tpm2.HandleOwner)
	if err != nil {
		return "", fmt.Errorf("Hash failed unexpectedly: %v", err)
	}
	// signer cannot sign restricted Attestation keys yet
	// https://pkg.go.dev/github.com/google/go-tpm-tools@v0.3.1/client#Key.SignData

	// cryptoSigner, err := kk.GetSigner()
	// if err != nil {
	// 	return "", fmt.Errorf("tpmjwt: can't get Signer %s: %v", config.TPMDevice, err)
	// }
	//signedBytes, err := cryptoSigner.Sign(config.TPMDevice, digest, s.hasher)
	// if err != nil {
	// 	return "", fmt.Errorf("tpmjwt: can't Sign %s: %v", config.TPMDevice, err)
	// }

	// So for now we do this the long way
	//   https://github.com/salrashid123/tpm2/tree/master/sign_with_ak
	sig, err := tpm2.Sign(config.TPMDevice, config.Key.Handle(), "", digest[:], hashValidation, &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %v", err)
	}

	signedBytes := []byte(sig.RSA.Signature)

	return base64.RawURLEncoding.EncodeToString(signedBytes), err
}

func TPMVerfiyKeyfunc(ctx context.Context, config *TPMConfig) (jwt.Keyfunc, error) {
	return func(token *jwt.Token) (interface{}, error) {
		return config.publicKeyFromTPM, nil
	}, nil
}

func (s *SigningMethodTPM) Verify(signingString, signature string, key interface{}) error {
	return s.override.Verify(signingString, signature, key)
}
