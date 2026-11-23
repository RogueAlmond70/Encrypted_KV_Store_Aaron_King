package chacha20_poly1305

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/internal"
	"golang.org/x/crypto/chacha20poly1305"
)

type CHACHA20_POLY1305 struct {
	logger internal.Logger
	AEAD   cipher.AEAD
}

func Create_CHACHA20_POLY1305(logger internal.Logger, key []byte) (*CHACHA20_POLY1305, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	CHAHA := CHACHA20_POLY1305{
		logger: logger,
		AEAD:   aead,
	}

	return &CHAHA, nil
}

func (c *CHACHA20_POLY1305) Encrypt(data []byte) ([]byte, error) {
	totalLen := c.AEAD.NonceSize() + len(data) + c.AEAD.Overhead()
	nonce := make([]byte, c.AEAD.NonceSize(), totalLen)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	ciphertext := c.AEAD.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

func (c *CHACHA20_POLY1305) Decrypt(cipherdata []byte) ([]byte, error) {
	if len(cipherdata) < c.AEAD.NonceSize()+c.AEAD.Overhead() {
		return nil, fmt.Errorf("failed to decrypt data - cipherdata too short") 
	}

	nonce, cipherdata := cipherdata[:c.AEAD.NonceSize()], cipherdata[c.AEAD.NonceSize():]

	return c.AEAD.Open(nil, nonce, cipherdata, nil)
}
