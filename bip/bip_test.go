package bip

import (
	"encoding/hex"
	"log"
	"strconv"
	"testing"

	bip32 "github.com/tyler-smith/go-bip32"
	bip39 "github.com/tyler-smith/go-bip39"
)

func TestBIP39(t *testing.T) {

	log.Default().Println("test bip039")

	entrypy, err := bip39.NewEntropy(256)
	// 创建随机熵字节
	if err != nil {
		log.Default().Fatal("err occoured: ", err)
	}
	words, err := bip39.NewMnemonic(entrypy)
	// 根据给定的熵字节返回助记词组成的字符串
	if err != nil {
		log.Default().Fatal("err occoured: ", err)
	}
	log.Default().Println("generate words: ", words)

	log.Default().Println("seed from words")
	seed := bip39.NewSeed(words, "")

	log.Default().Println("generate multi private key")
	key, err := bip32.NewMasterKey(seed)
	if err != nil {
		log.Default().Fatal("err occoured: ", err)
	}

	derivationPath := []uint32{
		bip32.FirstHardenedChild + 44,
		bip32.FirstHardenedChild + 60,
		bip32.FirstHardenedChild + 0,
		0,
		0,
	}
	var i uint32 = 0
	for ; i < 3; i++ {
		derivationPath[4] += i
		next := key
		for _, idx := range derivationPath {
			var err error
			next, err = next.NewChildKey(idx)
			if err != nil {
				log.Default().Println("err:", err)
				return
			}
		}
		log.Default().Println("generate key--" + strconv.FormatUint(uint64(i), 10) + "-------" + hex.EncodeToString(next.Key))
	}
}
