package nacl

import (
	"crypto/rand"
	"io"
	"reflect"
	"testing"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

func TestAssymetricSendNaclMessageFromAliceToBob(t *testing.T) {
	plaintext := "The quick brown fox jumps over the lazy dog"
	pkalice, skalice, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("Cant create keys for alice: %v", err)
	}

	pkbob, skbob, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("Cant create keys for bob: %v", err)
	}

	t.Log("Original text:", plaintext)
	t.Log("NACL box seal/open")

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		t.Errorf("Cant create random nonce for message: %v", err)
	}

	encrypted := box.Seal(nonce[:], []byte(plaintext), &nonce, pkbob, skalice)
	t.Logf("Alice send encrypted message to Bob: %x\n", encrypted)

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])

	decrypted, ok := box.Open(nil, encrypted[24:], &decryptNonce, pkalice, skbob)
	if !ok {
		t.Errorf("Something went wrong decripting the message")
	}

	if !reflect.DeepEqual(plaintext, string(decrypted)) {
		t.Errorf("The messages are not equal. Expected = %v, got: %v", plaintext, string(decrypted))
	}

	t.Log("Bob read the message:", string(decrypted))
}

func TestSymetricMessageSealOpen(t *testing.T) {

	plaintext := "The quick brown fox jumps over the lazy dog"

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		t.Errorf("Cant create random nonce for message: %v", err)
	}

	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		t.Errorf("Cant create random key for message: %v", err)
	}
	encrypted := make([]byte, len(nonce))
	copy(encrypted, nonce[:])
	encrypted = secretbox.Seal(encrypted, []byte(plaintext), &nonce, &key)

	t.Logf("Encrypted message: %x\n", encrypted)

	if len(encrypted) < (len(nonce) + secretbox.Overhead) {
		t.Errorf("Message size is wrong\n")
	}

	var recNonce [24]byte
	copy(recNonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], &recNonce, &key)
	if !ok {
		t.Errorf("Something went wrong decripting the message")
	}

	if !reflect.DeepEqual(plaintext, string(decrypted)) {
		t.Errorf("The messages are not equal. Expected = %v, got: %v", plaintext, string(decrypted))
	}

	t.Log("Message:", string(decrypted))

}
