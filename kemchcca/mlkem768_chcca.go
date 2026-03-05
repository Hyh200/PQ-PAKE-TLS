package kemchcca

import (
	"crypto/rand"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// MLKEM768CHCCA is an OW-ChCCA instantiation using ML-KEM-768.
// (IND-CCA2 security implies OW-ChCCA.)
type MLKEM768CHCCA struct {
	sch kem.Scheme
}

func NewMLKEM768CHCCA() *MLKEM768CHCCA {
	return &MLKEM768CHCCA{sch: mlkem768.Scheme()}
}

func (k *MLKEM768CHCCA) Name() string { return k.sch.Name() }

func (k *MLKEM768CHCCA) KeyGen() (pkBytes, skBytes []byte, err error) {
	pk, sk, err := k.sch.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	pkBytes, err = pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	skBytes, err = sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return pkBytes, skBytes, nil
}

func (k *MLKEM768CHCCA) Encap(pkBytes []byte) (ct, ss []byte, err error) {
	pk, err := k.sch.UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		return nil, nil, err
	}
	ct, ss, err = k.sch.Encapsulate(pk)
	return
}

func (k *MLKEM768CHCCA) Decap(skBytes, ct []byte) (ss []byte, err error) {
	sk, err := k.sch.UnmarshalBinaryPrivateKey(skBytes)
	if err != nil {
		return nil, err
	}
	ss, err = k.sch.Decapsulate(sk, ct)
	return
}

func (k *MLKEM768CHCCA) Sizes() (pk, sk, ct, ss int) {
	return k.sch.PublicKeySize(), k.sch.PrivateKeySize(), k.sch.CiphertextSize(), k.sch.SharedKeySize()
}

// Helper to get a random seed (used only in tests/examples).
func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
