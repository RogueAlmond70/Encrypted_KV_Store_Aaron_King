package aes_gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/internal"
)

type AES_GCM struct {
	logger internal.Logger
	AEAD   cipher.AEAD
}

func Create_ACS_GCM(logger internal.Logger, key []byte) (*AES_GCM, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	AES_GCM := AES_GCM{
		logger: logger,
		AEAD:   aead,
	}

	return &AES_GCM, nil
}

func (a *AES_GCM) Encrypt(data []byte) ([]byte, error) {
	totalLen := a.AEAD.NonceSize() + len(data) + a.AEAD.Overhead()
	nonce := make([]byte, a.AEAD.NonceSize(), totalLen)

	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	cipherdata := a.AEAD.Seal(nil, nonce, data, nil)
	return append(nonce, cipherdata...), nil
}

func (a *AES_GCM) Decrypt(cipherdata []byte) ([]byte, error) {
	if len(cipherdata) < a.AEAD.NonceSize()+a.AEAD.Overhead() {
		return nil, fmt.Errorf("failed to decrypt data: cipherdata too short")
	}

	nonce, ciphertext := cipherdata[:a.AEAD.NonceSize()], cipherdata[a.AEAD.NonceSize():]

	return a.AEAD.Open(nil, nonce, ciphertext, nil)
}
