package kdf

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func TestKeyDerivationFunction(t *testing.T) {
	hash := sha256.New
	// Master secret
	master := []byte{0x00, 0x01, 0x02, 0x03}

	// Master key will split into 3 crypto keys
	// Non-secret salt, optional(can be nil)
	// Recomended: hash-length random value

	salt := make([]byte, hash().Size())
	if _, err := rand.Read(salt); err != nil {
		t.Errorf("Cant create salt: %v\n", err)
	}

	// Non-secret context info, optional (can be nil)
	info := []byte{}
	mhkdf := hkdf.New(hash, master, salt, info)
	var keys [][]byte

	for i := 0; i < 3; i++ {
		key := make([]byte, 16)
		if _, err := io.ReadFull(mhkdf, key); err != nil {
			t.Errorf("Cant derive keys: %v\n", err)
		}
		keys = append(keys, key)
		t.Logf("HKDF key #%d: %x\n", i+1, key)
	}
	for i := range keys {
		t.Logf("Key #%d: %v\n", i+1, !bytes.Equal(keys[i], make([]byte, 16)))
	}

}
