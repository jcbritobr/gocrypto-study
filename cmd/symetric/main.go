package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySize   = 32
	nonceSize = 24
)

var (
	errEncrypt = errors.New("secret: encryption failed")
	errDecrypt = errors.New("secret: decryption failed")
)

// generateKey creates a new random secret key
func generateKey() (*[keySize]byte, error) {
	key := new([keySize]byte)
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return nil, err
	}

	return key, nil
}

// generateNonce creates a new random nonce
func generateNonce() (*[nonceSize]byte, error) {
	nonce := new([nonceSize]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

func encrypt(key *[keySize]byte, message []byte) ([]byte, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, errEncrypt
	}
	out := make([]byte, len(nonce))
	copy(out, nonce[:])
	out = secretbox.Seal(out, message, nonce, key)
	return out, nil
}

func decrypt(key *[keySize]byte, message []byte) ([]byte, error) {
	if len(message) < (nonceSize + secretbox.Overhead) {
		return nil, errDecrypt
	}

	var nonce [nonceSize]byte
	copy(nonce[:], message[:nonceSize])
	out, ok := secretbox.Open(nil, message[nonceSize:], &nonce, key)
	if !ok {
		return nil, errDecrypt
	}
	return out, nil
}

func main() {
	fmt.Println("Generating key")
	key, err := generateKey()
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
