package test

import (
	tool "EncryptedTool/src"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestCurve25519GenerateKey(t *testing.T) {

	e := tool.NewCurrve25519ECDH()

	privKey, pubKey, err := e.GenerateKey(rand.Reader)

	if err != nil {
		t.Fatal(err.Error())
	}
	priv := *(privKey.(*[32]byte))
	pub := *(pubKey.(*[32]byte))
	fmt.Println("privateKey:")
	fmt.Println(hex.EncodeToString(priv[:]))
	fmt.Println("publicKey:")
	fmt.Println(hex.EncodeToString(pub[:]))
	// fmt.Println("address:")
}

func TestECD(t *testing.T) {

	e1 := tool.NewCurrve25519ECDH()

	E1PriveKey, E1PubKey, err := e1.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err.Error())
	}

	e2 := tool.NewCurrve25519ECDH()
	E2PriveKey, E2PubKey, err := e1.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err.Error())
	}

	secret1, err := e1.GenerateSharedSecret(E1PriveKey, E2PubKey)
	if err != nil {
		t.Fatal(err.Error())
	}

	secret2, err := e2.GenerateSharedSecret(E2PriveKey, E1PubKey)
	if err != nil {
		t.Fatal(err.Error())
	}

	if !bytes.Equal(secret1, secret2) {
		t.Fatalf("failed")
	}
}

func TestGenerate(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	a := new(big.Int)
	b, _ := a.SetString("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 0)
	res := key.PublicKey.X.Cmp(b)
	fmt.Println(res)
}
