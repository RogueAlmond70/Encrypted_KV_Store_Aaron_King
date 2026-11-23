package encryption

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"log/slog"
	"testing"
)

func discard() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func key32(t *testing.T) []byte {
	t.Helper()
	key, err := GenerateEncryptionKey(discard())
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length %d", len(key))
	}
	return key
}

func TestGenerateEncryptionKey(t *testing.T) {
	a := key32(t)
	b := key32(t)
	if bytes.Equal(a, b) {
		t.Fatal("two generated keys were identical")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintexts := [][]byte{
		[]byte("hello"),
		{},
		{0, 1, 2, 255},
	}
	algorithms := []string{"AES_GCM", "AES_GCM_SIV", "CHACHA20_POLY1305"}

	for _, algorithm := range algorithms {
		for _, plaintext := range plaintexts {
			key := key32(t)
			sealed, err := EncryptData(plaintext, key, "id", discard(), algorithm)
			if err != nil {
				t.Fatalf("%s encrypt: %v", algorithm, err)
			}
			if bytes.Equal(sealed, plaintext) && len(plaintext) > 0 {
				t.Fatalf("%s stored plaintext", algorithm)
			}
			got, err := DecryptData(sealed, key, "id", discard(), algorithm)
			if err != nil {
				t.Fatalf("%s decrypt: %v", algorithm, err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("%s round trip got %x want %x", algorithm, got, plaintext)
			}
		}
	}
}

func TestEncryptRejectsNilInputs(t *testing.T) {
	key := key32(t)
	if _, err := EncryptData(nil, key, "id", discard(), "AES_GCM"); err == nil {
		t.Fatal("nil data encrypted")
	}
	if _, err := EncryptData([]byte("x"), nil, "id", discard(), "AES_GCM"); err == nil {
		t.Fatal("nil key encrypted")
	}
}

func TestDecryptRejectsNilInputs(t *testing.T) {
	key := key32(t)
	if _, err := DecryptData(nil, key, "id", discard(), "AES_GCM"); err == nil {
		t.Fatal("nil data decrypted")
	}
	if _, err := DecryptData([]byte("x"), nil, "id", discard(), "AES_GCM"); err == nil {
		t.Fatal("nil key decrypted")
	}
}

func TestInvalidAlgorithm(t *testing.T) {
	key := key32(t)
	_, err := EncryptData([]byte("x"), key, "id", discard(), "ROT13")
	if !errors.Is(err, ErrInvalidAlgorithm) {
		t.Fatalf("encrypt err = %v", err)
	}
	_, err = DecryptData([]byte("x"), key, "id", discard(), "")
	if !errors.Is(err, ErrInvalidAlgorithm) {
		t.Fatalf("decrypt err = %v", err)
	}
}

func TestEncryptRejectsBadKeyLength(t *testing.T) {
	short := []byte("not-a-valid-key")
	for _, algorithm := range []string{"AES_GCM", "AES_GCM_SIV", "CHACHA20_POLY1305"} {
		_, err := EncryptData([]byte("x"), short, "id", discard(), algorithm)
		if err == nil || errors.Is(err, ErrInvalidAlgorithm) {
			t.Fatalf("%s err = %v", algorithm, err)
		}
	}
}

func TestDecryptRejectsTamperedAndTruncatedCiphertext(t *testing.T) {
	key := key32(t)
	for _, algorithm := range []string{"AES_GCM", "AES_GCM_SIV", "CHACHA20_POLY1305"} {
		sealed, err := EncryptData([]byte("hello"), key, "id", discard(), algorithm)
		if err != nil {
			t.Fatal(err)
		}
		tampered := bytes.Clone(sealed)
		tampered[len(tampered)-1] ^= 0xff
		if _, err := DecryptData(tampered, key, "id", discard(), algorithm); err == nil {
			t.Fatalf("%s accepted tampered ciphertext", algorithm)
		}
		if _, err := DecryptData([]byte{1, 2, 3}, key, "id", discard(), algorithm); err == nil {
			t.Fatalf("%s accepted truncated ciphertext", algorithm)
		}
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	sealed, err := EncryptData([]byte("hello"), key32(t), "id", discard(), "AES_GCM")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptData(sealed, key32(t), "id", discard(), "AES_GCM"); err == nil {
		t.Fatal("decrypted with a different key")
	}
}

func TestKeyHash(t *testing.T) {
	sum := sha256.Sum256([]byte("key"))
	got, err := KeyHash([]byte("key"), discard())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, sum[:]) {
		t.Fatalf("hash %x", got)
	}
	if _, err := KeyHash(nil, discard()); err == nil {
		t.Fatal("hashed a nil key")
	}
}

func TestHashVerify(t *testing.T) {
	key := []byte("key")
	sum := sha256.Sum256(key)
	ok, err := HashVerify(key, sum[:], discard())
	if !ok || err != nil {
		t.Fatalf("match ok=%v err=%v", ok, err)
	}

	other := sha256.Sum256([]byte("other"))
	ok, err = HashVerify(key, other[:], discard())
	if ok || err == nil {
		t.Fatalf("mismatch ok=%v err=%v", ok, err)
	}

	ok, err = HashVerify(key, sum[:len(sum)-1], discard())
	if ok || err == nil {
		t.Fatalf("short hash ok=%v err=%v", ok, err)
	}

	if ok, err = HashVerify(nil, sum[:], discard()); ok || err == nil {
		t.Fatalf("nil key ok=%v err=%v", ok, err)
	}
	if ok, err = HashVerify(key, nil, discard()); ok || err == nil {
		t.Fatalf("nil hash ok=%v err=%v", ok, err)
	}
}
