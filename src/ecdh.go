package src

import (
	"crypto"
	"io"
)

type ECDH interface {
	GenerateKey(io.Reader) (crypto.PrivateKey, crypto.PublicKey, error)

	Marshal(crypto.PublicKey) []byte

	Unmarshal([]byte) (crypto.PublicKey, bool)

	GenerateSharedSecret(crypto.PrivateKey, crypto.PublicKey) ([]byte, error)
}
