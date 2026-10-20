// Run with: go run tests/fixtures/generate-go-compat.go
// Synthetic data only. These are the standard-library algorithms and layouts
// used at Go baseline 6fc5145a7f0983dd1a3c92a44216ec9de041df55:
// internal/auth token/CSRF and email secret nonce-prefix/AAD encoding.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func main() {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 42
	}
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	plaintext := []byte(`{"To":"compat@example.com","Subject":"Go fixture","Body":"Synthetic message"}`)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	sealed := gcm.Seal(append([]byte{}, nonce...), nonce, plaintext, []byte("email-outbox/v1"))
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("foltivo/session/csrf/v1"))
	result := map[string]string{
		"baseline": "6fc5145a7f0983dd1a3c92a44216ec9de041df55",
		"key":      base64.StdEncoding.EncodeToString(key),
		"purpose":  "email-outbox/v1", "plaintext": string(plaintext),
		"ciphertext": base64.StdEncoding.EncodeToString(sealed),
		"token":      token, "csrf": base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	}
	output, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(output))
}
