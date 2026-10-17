package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
)

// Secrets encrypts recoverable factor and pending email secrets. Keep its key
// persistent and external to the database; replacing it requires key migration.
type Secrets struct{ aead cipher.AEAD }

func NewSecrets(encoded string) (*Secrets, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, Validation("AUTH_ENCRYPTION_KEY must encode exactly 32 random bytes.")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, Unavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, Unavailable
	}
	return &Secrets{aead: aead}, nil
}
func (s *Secrets) Seal(plain []byte, purpose string) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, Unavailable
	}
	return s.aead.Seal(nonce, nonce, plain, []byte(purpose)), nil
}
func (s *Secrets) Open(data []byte, purpose string) ([]byte, error) {
	if len(data) < s.aead.NonceSize() {
		return nil, Unavailable
	}
	plain, err := s.aead.Open(nil, data[:s.aead.NonceSize()], data[s.aead.NonceSize():], []byte(purpose))
	return plain, safe(err)
}
