package hash

import (
	"crypto/sha1"
	"testing"
)

func TestShaFamily(t *testing.T) {
	message := "the quick brown fox jumps over the lazy dog"
	t.Log(message)
	h := sha1.New()
	h.Write([]byte(message))
	bs := h.Sum(nil)
	t.Logf("SHA1 hex: %x\n", bs)
}
