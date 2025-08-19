package tpmjwt

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type Session interface {
	GetSession() (auth tpm2.Session, closer func() error, err error) // this supplies the session handle to the library
}

// for pcr sessions
type PCRSession struct {
	rwr              transport.TPM
	sel              []tpm2.TPMSPCRSelection
	digest           tpm2.TPM2BDigest
	encryptionHandle tpm2.TPMHandle
}

var _ Session = (*PCRSession)(nil)

// Sets up a PCR session.  THe digest parameter signals what PCR digest to expect explicitly.
// Normally, just setting the pcr bank numbers (i.e tpm2.TPMSPCRSelection) will enforce pcr compliance
//
//	useing the original PCR values the key was bound to
//
// If you specify the pcrselection and digest, the digest value you specify is checked explictly vs implictly.
//
//	The digest value lets you 'see' the digest the key is bound to upfront.
//	if the digest is incorrect, you'll see
//	  "tpmjwt: error getting session TPM_RC_VALUE (parameter 1): value is out of range or is not correct for the context"
func NewPCRSession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection, digest tpm2.TPM2BDigest, encryptionHandle tpm2.TPMHandle) (PCRSession, error) {
	return PCRSession{rwr, sel, digest, encryptionHandle}, nil
}

func (p PCRSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	var ePubName *tpm2.TPMTPublic
	if p.encryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: p.encryptionHandle,
		}.Execute(p.rwr)
		if err != nil {
			return nil, nil, err
		}
		ePubName, err = encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, nil, err
		}
	}

	var pcr_sess tpm2.Session
	var pcr_cleanup func() error

	if p.encryptionHandle != 0 {
		pcr_sess, pcr_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(p.encryptionHandle, *ePubName))
		if err != nil {
			return nil, nil, err
		}
	} else {
		pcr_sess, pcr_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: pcr_sess.Handle(),
		PcrDigest:     p.digest,
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, pcr_cleanup, err
	}

	return pcr_sess, pcr_cleanup, nil
}

// for password sessions
type PasswordAuthSession struct {
	rwr              transport.TPM
	password         []byte
	encryptionHandle tpm2.TPMHandle
}

var _ Session = (*PasswordAuthSession)(nil)

func NewPasswordAuthSession(rwr transport.TPM, password []byte, encryptionHandle tpm2.TPMHandle) (PasswordAuthSession, error) {
	return PasswordAuthSession{rwr, password, encryptionHandle}, nil
}

func (p PasswordAuthSession) GetSession() (auth tpm2.Session, closer func() error, err error) {
	c := func() error { return nil }
	return tpm2.PasswordAuth(p.password), c, nil
}

// for password sessions
type PolicyPasswordSession struct {
	rwr              transport.TPM
	password         []byte
	encryptionHandle tpm2.TPMHandle
}

var _ Session = (*PolicyPasswordSession)(nil)

func NewPolicyPasswordSession(rwr transport.TPM, password []byte, encryptionHandle tpm2.TPMHandle) (PolicyPasswordSession, error) {
	return PolicyPasswordSession{rwr, password, encryptionHandle}, nil
}

func (p PolicyPasswordSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	var ePubName *tpm2.TPMTPublic
	if p.encryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: p.encryptionHandle,
		}.Execute(p.rwr)
		if err != nil {
			return nil, nil, err
		}
		ePubName, err = encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, nil, err
		}
	}
	// tpm2.Salted(p.encryptionHandle, *ePubName)
	sess, c, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(p.password)), tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(p.encryptionHandle, *ePubName)}...)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, c, err
	}

	return sess, c, nil
}

type PolicyAuthValueDuplicateSelectSession struct {
	rwr              transport.TPM
	password         []byte
	dupEKName        tpm2.TPM2BName
	encryptionHandle tpm2.TPMHandle
}

func NewPolicyAuthValueAndDuplicateSelectSession(rwr transport.TPM, password []byte, dupEKName tpm2.TPM2BName, encryptionHandle tpm2.TPMHandle) (PolicyAuthValueDuplicateSelectSession, error) {
	return PolicyAuthValueDuplicateSelectSession{rwr, password, dupEKName, encryptionHandle}, nil
}

func (p PolicyAuthValueDuplicateSelectSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	var ePubName *tpm2.TPMTPublic
	if p.encryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: p.encryptionHandle,
		}.Execute(p.rwr)
		if err != nil {
			return nil, nil, err
		}
		ePubName, err = encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, nil, err
		}
	}

	var pa_sess tpm2.Session
	var pa_cleanup func() error

	if p.encryptionHandle != 0 {
		pa_sess, pa_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(p.encryptionHandle, *ePubName))
		if err != nil {
			return nil, nil, err
		}
	} else {
		pa_sess, pa_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: pa_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, pa_cleanup, err
	}

	papgd, err := tpm2.PolicyGetDigest{
		PolicySession: pa_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, pa_cleanup, err
	}
	err = pa_cleanup()
	if err != nil {
		return nil, nil, err
	}

	var dupselect_sess tpm2.Session
	var dupselect_cleanup func() error
	// as the "new parent"

	if p.encryptionHandle != 0 {
		dupselect_sess, dupselect_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(p.encryptionHandle, *ePubName))
		if err != nil {
			return nil, nil, err
		}
	} else {
		dupselect_sess, dupselect_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyDuplicationSelect{
		PolicySession: dupselect_sess.Handle(),
		NewParentName: tpm2.TPM2BName(p.dupEKName),
	}.Execute(p.rwr)
	if err != nil {
		return nil, dupselect_cleanup, err
	}

	// calculate the digest
	dupselpgd, err := tpm2.PolicyGetDigest{
		PolicySession: dupselect_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, dupselect_cleanup, err
	}
	err = dupselect_cleanup()
	if err != nil {
		return nil, nil, err
	}

	var or_sess tpm2.Session
	var or_cleanup func() error
	// now create an OR session with the two above policies above

	if p.encryptionHandle != 0 {
		or_sess, or_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(p.password)), tpm2.Salted(p.encryptionHandle, *ePubName)}...)
		if err != nil {
			return nil, nil, err
		}
	} else {
		or_sess, or_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(p.password))}...)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: or_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, or_cleanup, err
	}
	_, err = tpm2.PolicyOr{
		PolicySession: or_sess.Handle(),
		PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{papgd.PolicyDigest, dupselpgd.PolicyDigest}},
	}.Execute(p.rwr)
	if err != nil {
		return nil, or_cleanup, err
	}

	return or_sess, or_cleanup, nil
}

type PCRAndDuplicateSelectSession struct {
	rwr              transport.TPM
	sel              []tpm2.TPMSPCRSelection
	digest           tpm2.TPM2BDigest
	password         []byte
	dupEKName        tpm2.TPM2BName
	encryptionHandle tpm2.TPMHandle
}

func NewPCRAndDuplicateSelectSession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection, digest tpm2.TPM2BDigest, password []byte, dupEKName tpm2.TPM2BName, encryptionHandle tpm2.TPMHandle) (PCRAndDuplicateSelectSession, error) {
	return PCRAndDuplicateSelectSession{rwr, sel, digest, password, dupEKName, encryptionHandle}, nil
}

func (p PCRAndDuplicateSelectSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	var ePubName *tpm2.TPMTPublic
	if p.encryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: p.encryptionHandle,
		}.Execute(p.rwr)
		if err != nil {
			return nil, nil, err
		}
		ePubName, err = encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, nil, err
		}
	}

	var pcr_sess tpm2.Session
	var pcr_cleanup func() error

	if p.encryptionHandle != 0 {
		pcr_sess, pcr_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(p.encryptionHandle, *ePubName))
		if err != nil {
			return nil, nil, err
		}
	} else {
		pcr_sess, pcr_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: pcr_sess.Handle(),
		PcrDigest:     p.digest,
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, pcr_cleanup, err
	}

	pcrpgd, err := tpm2.PolicyGetDigest{
		PolicySession: pcr_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, pcr_cleanup, err
	}
	err = pcr_cleanup()
	if err != nil {
		return nil, nil, err
	}

	var dupselect_sess tpm2.Session
	var dupselect_cleanup func() error
	// as the "new parent"

	if p.encryptionHandle != 0 {
		dupselect_sess, dupselect_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(p.encryptionHandle, *ePubName))
		if err != nil {
			return nil, nil, err
		}
	} else {
		dupselect_sess, dupselect_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyDuplicationSelect{
		PolicySession: dupselect_sess.Handle(),
		NewParentName: tpm2.TPM2BName(p.dupEKName),
	}.Execute(p.rwr)
	if err != nil {
		return nil, dupselect_cleanup, err
	}

	// calculate the digest
	dupselpgd, err := tpm2.PolicyGetDigest{
		PolicySession: dupselect_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, dupselect_cleanup, err
	}
	err = dupselect_cleanup()
	if err != nil {
		return nil, nil, err
	}

	var or_sess tpm2.Session
	var or_cleanup func() error
	// now create an OR session with the two above policies above

	if p.encryptionHandle != 0 {
		or_sess, or_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(p.password)), tpm2.Salted(p.encryptionHandle, *ePubName)}...)
		if err != nil {
			return nil, nil, err
		}
	} else {
		or_sess, or_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(p.password))}...)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: or_sess.Handle(),
		PcrDigest:     p.digest,
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, or_cleanup, err
	}

	_, err = tpm2.PolicyOr{
		PolicySession: or_sess.Handle(),
		PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{pcrpgd.PolicyDigest, dupselpgd.PolicyDigest}},
	}.Execute(p.rwr)
	if err != nil {
		return nil, or_cleanup, err
	}

	return or_sess, or_cleanup, nil
}

func getPCRMap(algo tpm2.TPMAlgID, pcrMap map[uint][]byte) (map[uint][]byte, []uint, []byte, error) {

	var hsh hash.Hash
	// https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/lib/tpm2_openssl.c#L206
	if algo == tpm2.TPMAlgSHA1 {
		hsh = sha1.New()
	}
	if algo == tpm2.TPMAlgSHA256 {
		hsh = sha256.New()
	}

	if algo == tpm2.TPMAlgSHA1 || algo == tpm2.TPMAlgSHA256 {
		for uv, v := range pcrMap {
			pcrMap[uint(uv)] = v
			hsh.Write(v)
		}
	} else {
		return nil, nil, nil, fmt.Errorf("unknown Hash Algorithm for TPM PCRs %v", algo)
	}

	pcrs := make([]uint, 0, len(pcrMap))
	for k := range pcrMap {
		pcrs = append(pcrs, k)
	}

	return pcrMap, pcrs, hsh.Sum(nil), nil
}
