package encryption

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	aes_gcm "github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/encryption/aes-gcm"
	aes_gcm_siv "github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/encryption/aes-gcm-siv"
	chacha20_poly1305 "github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/encryption/chacha20-poly1305"
	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/internal"
)

// ErrInvalidAlgorithm is returned when the named cipher is not one of
// AES_GCM, AES_GCM_SIV, or CHACHA20_POLY1305.
var ErrInvalidAlgorithm = errors.New("invalid cipher type")

func GenerateEncryptionKey(logger internal.Logger) ([]byte, error) {
	key := make([]byte, 32)

	_, err := rand.Read(key) // Note - this can only return an error on legacy linux systems
	if err != nil {
		logger.Error("failed to generate encryption key", "error", err)
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}
	return key, nil
}

func EncryptData(data []byte, encryptionKey []byte, id string, logger internal.Logger, algorithm string) ([]byte, error) {
	if data == nil {
		logger.Error("failed to encrypt data", "reason", "nil data")
		return nil, fmt.Errorf("failed to encrypt data - nil data")
	}
	if encryptionKey == nil {
		logger.Error("failed to encrypt data", "reason", "nil encryption key")
		return nil, fmt.Errorf("failed to encrypt data - nil encryption key")
	}

	switch algorithm {
	case "AES_GCM_SIV":
		c, err := aes_gcm_siv.Create_ACS_GCM_SIV(logger, encryptionKey)
		if err != nil {
			logger.Error("failed to create acs gsm siv", "error", err)
			return nil, fmt.Errorf("failed to encrypt data - failed to create acs gsm siv: %w", err)
		}
		data, err := c.Encrypt(data)
		if err != nil {
			logger.Error("failed to encrypt data", "error", err)
			return nil, fmt.Errorf("failed to encrypt data: %w", err)
		}
		return data, nil

	case "CHACHA20_POLY1305":
		c, err := chacha20_poly1305.Create_CHACHA20_POLY1305(logger, encryptionKey)
		if err != nil {
			logger.Error("failed to create chacha20 poly1305", "error", err)
			return nil, fmt.Errorf("failed to encrypt data - failed to create chacha20 poly1305: %w", err)
		}
		data, err := c.Encrypt(data)
		if err != nil {
			logger.Error("failed to encrypt data", "error", err)
			return nil, fmt.Errorf("failed to encrypt data: %w", err)
		}
		return data, nil

	case "AES_GCM":
		c, err := aes_gcm.Create_ACS_GCM(logger, encryptionKey)
		if err != nil {
			logger.Error("failed to create acs gcm", "error", err)
			return nil, fmt.Errorf("failed to encrypt data - failed to create acs gsm: %w", err)
		}
		data, err := c.Encrypt(data)
		if err != nil {
			logger.Error("failed to encrypt data", "error", err)
			return nil, fmt.Errorf("failed to encrypt data: %w", err)
		}
		return data, nil

	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidAlgorithm, algorithm)
	}
}

func DecryptData(data []byte, encryptionKey []byte, id string, logger internal.Logger, algorithm string) ([]byte, error) {
	if data == nil {
		logger.Error("failed to decrypt data", "reason", "nil data")
		return nil, fmt.Errorf("failed to decrypt data - nil data")
	}
	if encryptionKey == nil {
		logger.Error("failed to decrypt data", "reason", "nil encryption key")
		return nil, fmt.Errorf("failed to decrypt data - nil encryption key")
	}

	switch algorithm {
	case "AES_GCM_SIV":
		c, err := aes_gcm_siv.Create_ACS_GCM_SIV(logger, encryptionKey)
		if err != nil {
			logger.Error("failed to create acs gsm siv", "error", err)
			return nil, fmt.Errorf("failed to decrypt data - failed to create acs gsm siv: %w", err)
		}
		data, err := c.Decrypt(data)
		if err != nil {
			logger.Error("failed to decrypt data", "error", err)
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}
		return data, nil

	case "CHACHA20_POLY1305":
		c, err := chacha20_poly1305.Create_CHACHA20_POLY1305(logger, encryptionKey)
		if err != nil {
			logger.Error("failed to create chacha20 poly1305", "error", err)
			return nil, fmt.Errorf("failed to decrypt data - failed to create chacha20 poly1305: %w", err)
		}
		data, err := c.Decrypt(data)
		if err != nil {
			logger.Error("failed to decrypt data", "error", err)
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}
		return data, nil

	case "AES_GCM":
		c, err := aes_gcm.Create_ACS_GCM(logger, encryptionKey)
		if err != nil {
			logger.Error("failed to create acs gcm", "error", err)
			return nil, fmt.Errorf("failed to decrypt data - failed to create acs gsm: %w", err)
		}
		data, err := c.Decrypt(data)
		if err != nil {
			logger.Error("failed to decrypt data", "error", err)
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}
		return data, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidAlgorithm, algorithm)
	}
}

func KeyHash(key []byte, logger internal.Logger) ([]byte, error) {
	if key == nil {
		logger.Error("failed to hash encryption key", "no key provided")
		return nil, fmt.Errorf("failed to hash encryption key - no key provided")
	}
	h := sha256.New()
	h.Write(key)
	hashed := h.Sum(nil)
	return hashed, nil
}

func HashVerify(key []byte, expectedHash []byte, logger internal.Logger) (bool, error) {
	if key == nil {
		logger.Error("failed to verify encryption key hash", "no key provided")
		return false, fmt.Errorf("failed to verify encryption key hash - no key provided")
	}
	if expectedHash == nil {
		logger.Error("failed to verify encryption key hash", "nil hash provided")
		return false, fmt.Errorf("failed to verify encryption key hash - nil hash provided")
	}
	storedHash, err := KeyHash(key, logger)
	if err != nil {
		logger.Error("failed to verify encryption key hash", "error", err)
		return false, fmt.Errorf("failed to verify encryption key hash: %w", err)
	}
	if len(expectedHash) != sha256.Size {
		logger.Error("failed to verify encryption key hash", "provided encryption key hash does not match")
		return false, fmt.Errorf("failed to verify encryption key hash - provided encryption key hash does not match")
	}

	if subtle.ConstantTimeCompare(expectedHash, storedHash) != 1 {
		logger.Error("failed to verify encryption key hash", "provided encryption key hash does not match")
		return false, fmt.Errorf("failed to verify encryption key hash - provided encryption key hash does not match")
	}
	return true, nil
}
