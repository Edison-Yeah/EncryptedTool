package src

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"io"

	s256 "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type Secp256k1ECDH struct {
	ECDH
	curve elliptic.Curve
}

// type ellipticPublicKey struct {
// 	elliptic.Curve
// 	X, Y *big.Int
// }

var _ ECDH = (*Secp256k1ECDH)(nil)

func NewSecp256k1ECDH(curve elliptic.Curve) ECDH {
	return &Secp256k1ECDH{curve: curve}
}

func (e *Secp256k1ECDH) GenerateKey(rand io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {

	ecdsaPriv, err := ecdsa.GenerateKey(s256.S256(), rand)
	if err != nil {
		return nil, nil, err
	}
	pubKey := elliptic.Marshal(s256.S256(), ecdsaPriv.X, ecdsaPriv.Y)

	privKey := make([]byte, 32)
	blob := ecdsaPriv.D.Bytes()
	copy(privKey[32-len(blob):], blob)

	return privKey, pubKey, nil
}

func (e *Secp256k1ECDH) Marshal(p crypto.PublicKey) []byte {
	return (*(p.(*[]byte)))[:]
}

func (e *Secp256k1ECDH) Unmarshal(data []byte) (crypto.PublicKey, bool) {
	return data, false
}

func (e *Secp256k1ECDH) GenerateSharedSecret(privKey crypto.PrivateKey, pubKey crypto.PublicKey) ([]byte, error) {
	priv := new(ecdsa.PrivateKey)
	priv.Curve = s256.S256()
	// e.curve.ScalarBaseMult(e.Marshal(pubKey))
	return nil, nil
}
