package encoding

import (
	"encoding/base64"
	"testing"
)

func TestUrlEncoding(t *testing.T) {
	message := "http://www.google.com"
	encoded := base64.URLEncoding.EncodeToString([]byte(message))
	t.Log(string(encoded))
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		t.Errorf("Cant decode the message %v", err)
	}

	t.Log("Decoded message:\n", string(decoded))
}
