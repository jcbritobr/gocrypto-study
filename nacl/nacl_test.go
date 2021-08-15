package nacl

import (
	"crypto/rand"
	"io"
	"reflect"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestSendNaclMessageFromAliceToBob(t *testing.T) {
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
