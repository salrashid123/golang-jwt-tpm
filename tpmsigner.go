package tpmjwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"math/big"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	_ "crypto/sha256"
)

// Much of this implementation is inspired templated form [gcp-jwt-go](https://github.com/someone1/gcp-jwt-go)

type TPMConfig struct {
	TPMDevice   io.ReadWriteCloser
	NamedHandle tpm2.NamedHandle
	//Name             tpm2.TPM2BName
	AuthSession      Session          // If the key needs a session, supply one as the `tpmjwt.Session`
	KeyID            string           // (optional) the TPM keyID (normally the key "Name")
	publicKeyFromTPM crypto.PublicKey // the public key as read from KeyHandleFile, KeyHandleNV
	name             tpm2.TPM2BName
	EncryptionHandle tpm2.TPMHandle   // (optional) handle to use for transit encryption
	EncryptionPub    *tpm2.TPMTPublic // (optional) public key to use for transit encryption
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
	if val.TPMDevice == nil || &val.NamedHandle == nil {
		return nil, fmt.Errorf("tpmjwt: tpm device or key not set")
	}
	rwr := transport.FromReadWriter(val.TPMDevice)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(val.NamedHandle.HandleValue()),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("tpmjwt: error executing tpm2.ReadPublic %v", err)
	}

	outPub, err := pub.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpmjwt: error reading public contexts %v", err)
	}

	val.name = pub.Name

	var keyPub crypto.PublicKey

	switch outPub.Type {
	case tpm2.TPMAlgRSA:
		rsaDetail, err := outPub.Parameters.RSADetail()
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: error reading rsa public %v", err)
		}
		rsaUnique, err := outPub.Unique.RSA()
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: error reading rsa unique %v", err)
		}

		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: Failed to get rsa public key: %v", err)
		}
		keyPub = rsaPub
	case tpm2.TPMAlgECC:
		ecDetail, err := outPub.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: error reading ec details %v", err)
		}
		crv, err := ecDetail.CurveID.Curve()
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: error reading ecc curve %v", err)
		}
		eccUnique, err := outPub.Unique.ECC()
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: error reading ecc unique %v", err)
		}

		pubKey := &ecdsa.PublicKey{
			Curve: crv,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
		keyPub = pubKey
	default:
		return nil, fmt.Errorf("tpmjwt: unsupported Algorithm %v", outPub.Type)
	}

	val.publicKeyFromTPM = keyPub
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
	var tsig []byte

	rwr := transport.FromReadWriter(config.TPMDevice)

	var sess tpm2.Session
	//  check if we should use parameter encryption...if so, just use the EK for now
	if config.EncryptionHandle != 0 && config.EncryptionPub != nil {
		sess = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(config.EncryptionHandle, *config.EncryptionPub))
	} else {
		sess = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn))
	}

	h, err := tpm2.Hash{
		Hierarchy: tpm2.TPMRHEndorsement,
		HashAlg:   tpm2.TPMAlgSHA256,
		Data: tpm2.TPM2BMaxBuffer{
			Buffer: []byte(signingString),
		},
	}.Execute(rwr, sess)
	if err != nil {
		return nil, fmt.Errorf("tpmjwt: failed to generate hash from TPM %v", err)
	}

	var se tpm2.Session
	if config.AuthSession != nil {
		var closer func() error
		se, closer, err = config.AuthSession.GetSession()
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: error getting session %s", s.Alg())
		}
		defer closer()
	} else {
		se = tpm2.PasswordAuth(nil)
	}
	switch pub := config.publicKeyFromTPM.(type) {
	case *rsa.PublicKey:
		if s.Alg() == "RS256" {

			rspSign, err := tpm2.Sign{
				KeyHandle: tpm2.AuthHandle{
					Handle: config.NamedHandle.Handle,
					Name:   config.NamedHandle.Name,
					Auth:   se,
				},
				Digest: tpm2.TPM2BDigest{
					Buffer: h.OutHash.Buffer,
				},
				InScheme: tpm2.TPMTSigScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUSigScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSchemeHash{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				Validation: tpm2.TPMTTKHashCheck{
					Tag:       tpm2.TPMSTHashCheck,
					Hierarchy: tpm2.TPMRHEndorsement,
					Digest: tpm2.TPM2BDigest{
						Buffer: h.Validation.Digest.Buffer,
					},
				},
			}.Execute(rwr, sess)
			if err != nil {
				return nil, fmt.Errorf("tpmjwt: can't Sign: %v", err)
			}

			rsig, err := rspSign.Signature.Signature.RSASSA()
			if err != nil {
				return nil, fmt.Errorf("tpmjwt: error getting rsa signature: %v", err)
			}
			tsig = rsig.Sig.Buffer

		} else if s.Alg() == "PS256" {
			rspSign, err := tpm2.Sign{
				KeyHandle: tpm2.AuthHandle{
					Handle: config.NamedHandle.Handle,
					Name:   config.NamedHandle.Name,
					Auth:   se,
				},
				Digest: tpm2.TPM2BDigest{
					Buffer: h.OutHash.Buffer,
				},
				InScheme: tpm2.TPMTSigScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUSigScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSchemeHash{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				Validation: tpm2.TPMTTKHashCheck{
					Tag:       tpm2.TPMSTHashCheck,
					Hierarchy: tpm2.TPMRHEndorsement,
					Digest: tpm2.TPM2BDigest{
						Buffer: h.Validation.Digest.Buffer,
					},
				},
			}.Execute(rwr, sess)
			if err != nil {
				return nil, fmt.Errorf("tpmjwt: can't Sign pss %v", err)
			}

			rsig, err := rspSign.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, fmt.Errorf("tpmjwt: error getting rsa pss signature %v", err)
			}

			tsig = rsig.Sig.Buffer
		} else {
			return nil, fmt.Errorf("tpmjwt: unsupported rsa algorithm %s", s.Alg())
		}

	case *ecdsa.PublicKey:
		if s.Alg() == "ES256" {
			rspSign, err := tpm2.Sign{
				KeyHandle: tpm2.AuthHandle{
					Handle: config.NamedHandle.Handle,
					Name:   config.NamedHandle.Name,
					Auth:   se,
				},
				Digest: tpm2.TPM2BDigest{
					Buffer: h.OutHash.Buffer,
				},
				InScheme: tpm2.TPMTSigScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUSigScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSchemeHash{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				Validation: tpm2.TPMTTKHashCheck{
					Tag:       tpm2.TPMSTHashCheck,
					Hierarchy: tpm2.TPMRHEndorsement,
					Digest: tpm2.TPM2BDigest{
						Buffer: h.Validation.Digest.Buffer,
					},
				},
			}.Execute(rwr, sess)
			if err != nil {
				return nil, fmt.Errorf("tpmjwt: can't Sign ecc: %v", err)
			}

			rsig, err := rspSign.Signature.Signature.ECDSA()
			if err != nil {
				return nil, fmt.Errorf("tpmjwt: getting rsa ecc signature: %v", err)
			}
			out := append(rsig.SignatureR.Buffer, rsig.SignatureS.Buffer...)
			return out, nil

		} else {
			return nil, fmt.Errorf("tpmjwt: unsupported EC algorithm %s", s.Alg())
		}
	default:
		return nil, fmt.Errorf("tpmjwt: unsupported public key type %v", pub)
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

type Session interface {
	GetSession() (auth tpm2.Session, closer func() error, err error) // this supplies the session handle to the library
}

// for pcr sessions
type PCRSession struct {
	rwr transport.TPM
	sel []tpm2.TPMSPCRSelection
}

var _ Session = (*PCRSession)(nil)

func NewPCRSession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection) (PCRSession, error) {
	return PCRSession{rwr, sel}, nil
}

func (p PCRSession) GetSession() (auth tpm2.Session, closer func() error, err error) {
	sess, closer, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	return sess, closer, nil
}

// for password sessions
type PasswordSession struct {
	rwr      transport.TPM
	password []byte
}

var _ Session = (*PasswordSession)(nil)

func NewPasswordSession(rwr transport.TPM, password []byte) (PasswordSession, error) {
	return PasswordSession{rwr, password}, nil
}

func (p PasswordSession) GetSession() (auth tpm2.Session, closer func() error, err error) {
	c := func() error { return nil }
	return tpm2.PasswordAuth(p.password), c, nil
}
