package main

import (
	"encoding/hex"
	"fmt"

	"github.com/jcbritobr/cryptoexamples/cryptoutils"
	"golang.org/x/crypto/nacl/secretbox"
)

func encrypt(key *[cryptoutils.KeySize]byte, message []byte) ([]byte, error) {
	nonce, err := cryptoutils.GenerateNonce()
	if err != nil {
		return nil, cryptoutils.ErrEncrypt
	}
	out := make([]byte, len(nonce))
	copy(out, nonce[:])
	out = secretbox.Seal(out, message, nonce, key)
	return out, nil
}

func decrypt(key *[cryptoutils.KeySize]byte, message []byte) ([]byte, error) {
	if len(message) < (cryptoutils.NonceSize + secretbox.Overhead) {
		return nil, cryptoutils.ErrDecrypt
	}

	var nonce [cryptoutils.NonceSize]byte
	copy(nonce[:], message[:cryptoutils.NonceSize])
	out, ok := secretbox.Open(nil, message[cryptoutils.NonceSize:], &nonce, key)
	if !ok {
		return nil, cryptoutils.ErrDecrypt
	}
	return out, nil
}

func main() {
	fmt.Println("Generating key")
	key, err := cryptoutils.GenerateKey()
	if err != nil {
		panic(err)
	}
	fmt.Println(hex.EncodeToString(key[:]))

	message := "the quick brown fox jumps over the lazy dog"
	cryptoData, err := encrypt(key, []byte(message))
	if err != nil {
		panic(err)
	}

	fmt.Println("encrypted message:\n", hex.EncodeToString(cryptoData))

	decryptoData, err := decrypt(key, cryptoData)
	if err != nil {
		panic(err)
	}

	fmt.Println("decrypted message:\n", string(decryptoData))
}
