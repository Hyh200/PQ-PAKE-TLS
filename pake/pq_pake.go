package pake

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"

	"golang.org/x/crypto/hkdf"

	"kemowbench/kemchcca"
	"kemowbench/kempca"

	"kemowbench/sha3"
)

// Context bytes: in your figure this is ctx (e.g., transcript hash).
// For benchmarking we treat it as caller-provided.

// Run executes one full PAKE session following the figure.
// Returns the final session key K (both sides should match).
func Run(ctx []byte, pw []byte, kemS *kemchcca.MLKEM768CHCCA, kemC *kempca.PWKyberPKEKEM) (K []byte, err error) {
	// --- Registration ---
	pkS, skS, err := kemS.KeyGen()
	if err != nil {
		return nil, err
	}
	pkC, skC, err := kemC.DeriveKeyPairFromPassword(pw)
	if err != nil {
		return nil, err
	}
	_ = pkC // stored by server

	// --- Client -> Server: ct_s ---
	ctS, ssS_client, err := kemS.Encap(pkS)
	if err != nil {
		return nil, err
	}
	K1_client := hkdfExpand(ssS_client, nil, ctx, 32)
	_ = K1_client

	// --- Server: decap ct_s ---
	ssS_server, err := kemS.Decap(skS, ctS)
	if err != nil {
		return nil, err
	}
	K1_server := hkdfExpand(ssS_server, nil, ctx, 32)
	_ = K1_server

	// --- Server -> Client: e_c ---
	ctC, ssC_server, err := kemC.Encap(pkC)
	if err != nil {
		return nil, err
	}
	KIC_server := hkdfExpand(append(ssS_server, pkC...), nil, ctx, len(ctC))
	eC := icXor(KIC_server, ctx, ctC)
	AuthS := hmacTag(ssS_server, ssC_server, ctx)

	// --- Client: recover ct_c and decap ---
	KIC_client := hkdfExpand(append(ssS_client, pkC...), nil, ctx, len(eC))
	ctC_recovered := icXor(KIC_client, ctx, eC)
	ssC_client, err := kemC.Decap(skC, ctC_recovered)
	if err != nil {
		return nil, err
	}
	AuthC := hmacTag(ssS_client, ssC_client, ctx)
	if !hmac.Equal(AuthC, AuthS) {
		return nil, errors.New("Auth mismatch")
	}

	// --- Session key ---
	K = hkdfExpand(append(ssS_client, ssC_client...), nil, ctx, 32)
	return K, nil
}

func hkdfExpand(ikm, salt, info []byte, outLen int) []byte {
	h := sha256.New
	r := hkdf.New(h, ikm, salt, info)
	out := make([]byte, outLen)
	_, _ = r.Read(out)
	return out
}

func hmacTag(ssS, ssC, ctx []byte) []byte {
	mac := hmac.New(sha256.New, append(ssS, ssC...))
	mac.Write(ctx)
	return mac.Sum(nil)
}

// icXor is a lightweight "ideal-cipher-like" symmetric protection for ctC using a SHAKE256 keystream.
// e = ct XOR SHAKE256("ic"||key||0||ctx)[:len(ct)]
func icXor(key, ctx, ct []byte) []byte {
	xof := sha3.NewShake256()
	xof.Write([]byte("ic-v1"))
	xof.Write([]byte{0})
	xof.Write(key)
	xof.Write([]byte{0})
	xof.Write(ctx)
	ks := make([]byte, len(ct))
	xof.Read(ks)
	out := make([]byte, len(ct))
	for i := range ct {
		out[i] = ct[i] ^ ks[i]
	}
	return out
}

// Compile-time assertion that we imported hash (keeps gofmt from removing it in some environments)
var _ hash.Hash
