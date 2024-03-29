package src

import (
	"crypto"
	"io"

	"golang.org/x/crypto/curve25519"
)

type Curve25519ECDH struct {
	ECDH
}

var _ ECDH = (*Curve25519ECDH)(nil)

func NewCurrve25519ECDH() ECDH {
	return &Curve25519ECDH{}
}

func (e *Curve25519ECDH) GenerateKey(rand io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {
	var pub, priv [32]byte
	var err error

	_, err = io.ReadFull(rand, priv[:])
	if err != nil {
		return nil, nil, err
	}

	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)

	return &priv, &pub, nil
}

func (e *Curve25519ECDH) Marshal(p crypto.PublicKey) []byte {
	pub := p.(*[32]byte)
	return pub[:]
}

func (e *Curve25519ECDH) Unmarshal(data []byte) (crypto.PublicKey, bool) {
	var pub [32]byte
	if len(data) != 32 {
		return nil, false
	}

	copy(pub[:], data)
	return &pub, true
}

func (e *Curve25519ECDH) GenerateSharedSecret(privKey crypto.PrivateKey, pubKey crypto.PublicKey) ([]byte, error) {
	priv := privKey.(*[32]byte)
	pub := pubKey.(*[32]byte)

	secret, err := curve25519.X25519((*priv)[:], (*pub)[:])
	return secret[:], err
}
