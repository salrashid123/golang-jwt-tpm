package tpmjwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	jwt "github.com/golang-jwt/jwt/v5"

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
	SigningMethodTPMRS256 *SigningMethodTPM
	SigningMethodTPMPS256 *SigningMethodTPM
	SigningMethodTPMES256 *SigningMethodTPM
	errMissingConfig      = errors.New("tpmjwt: missing configuration in provided context")
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
	switch val.Key.PublicArea().Type {
	case tpm2.AlgRSA:
		// do optional validation
	case tpm2.AlgECC:
		// do optional validation
	default:
		return nil, fmt.Errorf("tpmjwt: unsupported Algorithm %s", val.Key.PublicArea().Type)
	}

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

	// PS256
	SigningMethodTPMPS256 = &SigningMethodTPM{
		"TPMPS256",
		jwt.SigningMethodPS256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodTPMPS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodTPMPS256
	})

	// ES256
	SigningMethodTPMES256 = &SigningMethodTPM{
		"TPMES256",
		jwt.SigningMethodES256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodTPMES256.Alg(), func() jwt.SigningMethod {
		return SigningMethodTPMES256
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

func (s *SigningMethodTPM) Sign(signingString string, key interface{}) ([]byte, error) {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return nil, jwt.ErrInvalidKey
	}
	config, ok := TPMFromContext(ctx)
	if !ok {
		return nil, errMissingConfig
	}
	tsig, err := config.Key.SignData([]byte(signingString))
	if err != nil {
		return nil, fmt.Errorf("tpmjwt: can't Sign %s: %v", config.TPMDevice, err)
	}

	if config.Key.PublicArea().Type == tpm2.AlgECC {
		// go-tpm-tools formats ECC signatures as asn1 but JWT expects raw so convert
		// the asn1 back
		epub, ok := config.Key.PublicKey().(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("tpmjwt: error converting ECC keytype %v", err)
		}
		curveBits := epub.Params().BitSize
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}
		out := make([]byte, 2*keyBytes)
		var sigStruct struct{ R, S *big.Int }
		_, err := asn1.Unmarshal(tsig, &sigStruct)
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: can't unmarshall ecc struct %v", err)
		}
		sigStruct.R.FillBytes(out[0:keyBytes])
		sigStruct.S.FillBytes(out[keyBytes:])
		return out, nil
	}
	return tsig, nil
}

func TPMVerfiyKeyfunc(ctx context.Context, config *TPMConfig) (jwt.Keyfunc, error) {
	return func(token *jwt.Token) (interface{}, error) {
		return config.publicKeyFromTPM, nil
	}, nil
}

func (s *SigningMethodTPM) Verify(signingString string, signature []byte, key interface{}) error {
	return s.override.Verify(signingString, []byte(signature), key)
}
