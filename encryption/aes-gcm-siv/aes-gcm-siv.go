package aes_gcm_siv

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/internal"
	"github.com/ericlagergren/siv"
)

type AES_GCM_SIV struct {
	logger internal.Logger
	AEAD   cipher.AEAD
}

func Create_ACS_GCM_SIV(logger internal.Logger, key []byte) (*AES_GCM_SIV, error) {
	aead, err := siv.NewGCM(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM-SIV: %w", err)
	}

	AES_GCM_SIV := AES_GCM_SIV{
		logger: logger,
		AEAD:   aead,
	}

	return &AES_GCM_SIV, nil
}

func (a *AES_GCM_SIV) Encrypt(data []byte) ([]byte, error) {
	totalLen := a.AEAD.NonceSize() + len(data) + a.AEAD.Overhead()
	nonce := make([]byte, a.AEAD.NonceSize(), totalLen)

	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	ciphertext := a.AEAD.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

func (a *AES_GCM_SIV) Decrypt(cipherdata []byte) ([]byte, error) {
	if len(cipherdata) < a.AEAD.NonceSize()+a.AEAD.Overhead() {
		return nil, fmt.Errorf("failed to decrypt data: cipherdata too short")
	}

	nonce, cipherdata := cipherdata[:a.AEAD.NonceSize()], cipherdata[a.AEAD.NonceSize():]

	return a.AEAD.Open(nil, nonce, cipherdata, nil)
}
