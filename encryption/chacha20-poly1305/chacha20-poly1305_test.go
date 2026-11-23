package chacha20_poly1305

import (
	"bytes"
	"crypto/rand"
	"log/slog"
	"testing"
)

func discard() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func key32(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestRoundTrip(t *testing.T) {
	c, err := Create_CHACHA20_POLY1305(discard(), key32(t))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := c.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Decrypt(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("got %q", got)
	}
}

func TestRejectsBadKey(t *testing.T) {
	if _, err := Create_CHACHA20_POLY1305(discard(), []byte("short")); err == nil {
		t.Fatal("accepted a short key")
	}
}

func TestDecryptRejectsTruncatedAndTampered(t *testing.T) {
	c, err := Create_CHACHA20_POLY1305(discard(), key32(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt([]byte{1, 2, 3}); err == nil {
		t.Fatal("accepted truncated ciphertext")
	}
	sealed, err := c.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0xff
	if _, err := c.Decrypt(sealed); err == nil {
		t.Fatal("accepted tampered ciphertext")
	}
}
