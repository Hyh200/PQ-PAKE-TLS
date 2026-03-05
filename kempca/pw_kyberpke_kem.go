package kempca

import (
	"crypto/rand"
	"errors"
	cpapke "github.com/cloudflare/circl/pke/kyber/kyber768"
	"kemowbench/sha3"
)

const (
	SharedKeySize = 32
	CoinsSize     = 32
)

// PWKyberPKEKEM is a simple PKE->KEM wrapper using Kyber768 CPA-PKE.
// The client keypair is deterministically derived from a password.
//
// Encap(pk): pick random k (32B), random coins (32B), ct = Enc(pk,k;coins), ss=k.
// Decap(sk,ct): ss = Dec(sk,ct).
//
// Security note: This is meant as an (N,μ)-OW-PCA-style *engineering instantiation*
// consistent with the PKE->KEM template referenced in Pan et al. The formal bound
// depends on the exact multi-user/multi-challenge model and PKE properties you assume.
type PWKyberPKEKEM struct{}

func NewPWKyberPKEKEM() *PWKyberPKEKEM { return &PWKyberPKEKEM{} }

func (k *PWKyberPKEKEM) Name() string { return "Kyber768-CPA(PKE->KEM, pw-derived keypair)" }

// DeriveKeyPairFromPassword derives (pk,sk) deterministically from pw.
// pw is treated as the entropy source; we domain-separate with a fixed label.
func (k *PWKyberPKEKEM) DeriveKeyPairFromPassword(pw []byte) (pkBytes, skBytes []byte, err error) {
	seed := deriveSeed(pw, cpapke.KeySeedSize)
	pk, sk := cpapke.NewKeyFromSeedMLKEM(seed) // deterministic

	pkBytes = make([]byte, cpapke.PublicKeySize)
	skBytes = make([]byte, cpapke.PrivateKeySize)
	pk.Pack(pkBytes)
	sk.Pack(skBytes)
	return pkBytes, skBytes, nil
}

// Encap uses the recipient public key.
func (k *PWKyberPKEKEM) Encap(pkBytes []byte) (ct, ss []byte, err error) {
	if len(pkBytes) != cpapke.PublicKeySize {
		return nil, nil, errors.New("bad pk size")
	}
	pk := new(cpapke.PublicKey)
	// CIRCL provides UnpackMLKEM for ML-KEM normalized pk; for CPA-PKE we use UnpackMLKEM too
	// because the encoding is identical for Kyber768 keys.
	if err := pk.UnpackMLKEM(pkBytes); err != nil {
		return nil, nil, err
	}

	ss = make([]byte, SharedKeySize)
	ct = make([]byte, cpapke.CiphertextSize)
	coins := make([]byte, CoinsSize)
	if _, err := rand.Read(ss); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(coins); err != nil {
		return nil, nil, err
	}

	pk.EncryptTo(ct, ss, coins)
	return ct, ss, nil
}

func (k *PWKyberPKEKEM) Decap(skBytes, ct []byte) (ss []byte, err error) {
	if len(skBytes) != cpapke.PrivateKeySize {
		return nil, errors.New("bad sk size")
	}
	if len(ct) != cpapke.CiphertextSize {
		return nil, errors.New("bad ct size")
	}
	sk := new(cpapke.PrivateKey)
	sk.Unpack(skBytes)
	ss = make([]byte, SharedKeySize)
	sk.DecryptTo(ss, ct)
	return ss, nil
}

func (k *PWKyberPKEKEM) Sizes() (pk, sk, ct, ss int) {
	return cpapke.PublicKeySize, cpapke.PrivateKeySize, cpapke.CiphertextSize, SharedKeySize
}

func deriveSeed(pw []byte, outLen int) []byte {
	xof := sha3.NewShake256()
	// Domain separation label
	xof.Write([]byte("pw-kem-seed-v1"))
	xof.Write([]byte{0})
	xof.Write(pw)
	seed := make([]byte, outLen)
	xof.Read(seed)
	return seed
}
