package random

import (
	"crypto/rand"
	"testing"
)

func TestRandomCryptoNumbersGeneration(t *testing.T) {
	buffer := make([]byte, 10)
	_, err := rand.Read(buffer)
	if err != nil {
		t.Errorf("Cant fill buffer with random data %v", err)
	}

	t.Log(buffer)
}
