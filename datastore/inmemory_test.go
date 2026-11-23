package datastore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"testing"

	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/encryption"
	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/internal"
)

func discard() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func newMem(algorithm string) *InMemoryDatastore {
	return NewInMemoryDatastore(discard(), internal.Config{EncryptionAlgorithm: algorithm})
}

func TestInMemoryRoundTrip(t *testing.T) {
	for _, algorithm := range []string{"AES_GCM", "AES_GCM_SIV", "CHACHA20_POLY1305"} {
		store := newMem(algorithm)
		plaintext := []byte("hello " + algorithm)
		key, err := store.Store(context.Background(), plaintext, "id")
		if err != nil {
			t.Fatalf("%s store: %v", algorithm, err)
		}

		entry := store.store["id"]
		sum := sha256.Sum256(key)
		if !bytes.Equal(entry.encryptionKey, sum[:]) {
			t.Fatalf("%s stored key is not the SHA-256 hash", algorithm)
		}
		if bytes.Equal(entry.encryptionKey, key) {
			t.Fatalf("%s stored the raw key", algorithm)
		}
		if bytes.Equal(entry.data, plaintext) {
			t.Fatalf("%s stored plaintext", algorithm)
		}
		if entry.encryptionAlgorithm != algorithm {
			t.Fatalf("algorithm %q", entry.encryptionAlgorithm)
		}

		got, err := store.Retrieve(context.Background(), "id", key)
		if err != nil {
			t.Fatalf("%s retrieve: %v", algorithm, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("%s got %q", algorithm, got)
		}

		updated := []byte("updated " + algorithm)
		if err := store.Update(context.Background(), updated, "id", key); err != nil {
			t.Fatalf("%s update: %v", algorithm, err)
		}
		got, err = store.Retrieve(context.Background(), "id", key)
		if err != nil {
			t.Fatalf("%s retrieve after update: %v", algorithm, err)
		}
		if !bytes.Equal(got, updated) {
			t.Fatalf("%s after update got %q", algorithm, got)
		}

		if err := store.Delete(context.Background(), "id", key); err != nil {
			t.Fatalf("%s delete: %v", algorithm, err)
		}
		_, err = store.Retrieve(context.Background(), "id", key)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s after delete err = %v", algorithm, err)
		}
	}
}

func TestInMemoryStoreKeepsEmptySlice(t *testing.T) {
	store := newMem("AES_GCM")
	key, err := store.Store(context.Background(), []byte{}, "empty")
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Retrieve(context.Background(), "empty", key)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %#v", got)
	}
}

func TestInMemoryRejectsInvalidInput(t *testing.T) {
	store := newMem("AES_GCM")
	ctx := context.Background()
	key := []byte("key")

	if _, err := store.Store(ctx, []byte("a"), ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("store empty id: %v", err)
	}
	if _, err := store.Store(ctx, nil, "id"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("store nil data: %v", err)
	}
	if _, err := store.Retrieve(ctx, "", key); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("retrieve empty id: %v", err)
	}
	if _, err := store.Retrieve(ctx, "id", nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("retrieve nil key: %v", err)
	}
	if err := store.Update(ctx, []byte("a"), "", key); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("update empty id: %v", err)
	}
	if err := store.Update(ctx, []byte("a"), "id", nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("update nil key: %v", err)
	}
	if err := store.Update(ctx, nil, "id", key); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("update nil data: %v", err)
	}
	if err := store.Delete(ctx, "", key); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("delete empty id: %v", err)
	}
	if err := store.Delete(ctx, "id", nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("delete nil key: %v", err)
	}
}

func TestInMemoryDuplicateDoesNotOverwrite(t *testing.T) {
	store := newMem("AES_GCM")
	key, err := store.Store(context.Background(), []byte("first"), "id")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Store(context.Background(), []byte("second"), "id"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate err = %v", err)
	}
	got, err := store.Retrieve(context.Background(), "id", key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("first")) {
		t.Fatalf("got %q", got)
	}
}

func TestInMemoryNotFoundAndWrongKey(t *testing.T) {
	store := newMem("AES_GCM")
	ctx := context.Background()
	if _, err := store.Retrieve(ctx, "missing", []byte("key")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retrieve: %v", err)
	}
	if err := store.Update(ctx, []byte("a"), "missing", []byte("key")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update: %v", err)
	}
	if err := store.Delete(ctx, "missing", []byte("key")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete: %v", err)
	}

	key, err := store.Store(ctx, []byte("secret"), "id")
	if err != nil {
		t.Fatal(err)
	}
	wrong := []byte("not-the-key")
	if _, err := store.Retrieve(ctx, "id", wrong); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("retrieve wrong key: %v", err)
	}
	if _, err := store.Retrieve(ctx, "id", []byte{}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("retrieve empty key: %v", err)
	}
	if err := store.Update(ctx, []byte("changed"), "id", wrong); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("update wrong key: %v", err)
	}
	if err := store.Delete(ctx, "id", wrong); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("delete wrong key: %v", err)
	}
	got, err := store.Retrieve(ctx, "id", key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("entry changed to %q", got)
	}
}

func TestInMemoryCancelledContext(t *testing.T) {
	store := newMem("AES_GCM")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := store.Store(ctx, []byte("a"), "id"); !errors.Is(err, context.Canceled) {
		t.Fatalf("store: %v", err)
	}
	if len(store.store) != 0 {
		t.Fatal("store wrote an entry after cancel")
	}
	if _, err := store.Retrieve(ctx, "id", []byte("key")); !errors.Is(err, context.Canceled) {
		t.Fatalf("retrieve: %v", err)
	}
	if err := store.Update(ctx, []byte("a"), "id", []byte("key")); !errors.Is(err, context.Canceled) {
		t.Fatalf("update: %v", err)
	}
	if err := store.Delete(ctx, "id", []byte("key")); !errors.Is(err, context.Canceled) {
		t.Fatalf("delete: %v", err)
	}
}

func TestInMemoryInvalidAlgorithmDoesNotWrite(t *testing.T) {
	store := newMem("ROT13")
	_, err := store.Store(context.Background(), []byte("a"), "id")
	if !errors.Is(err, encryption.ErrInvalidAlgorithm) {
		t.Fatalf("err = %v", err)
	}
	if _, ok := store.store["id"]; ok {
		t.Fatal("wrote an entry for an unknown algorithm")
	}
}

func TestInMemoryUpdateKeepsStoredAlgorithm(t *testing.T) {
	store := newMem("AES_GCM")
	key, err := store.Store(context.Background(), []byte("first"), "id")
	if err != nil {
		t.Fatal(err)
	}
	store.cfg.EncryptionAlgorithm = "CHACHA20_POLY1305"
	if err := store.Update(context.Background(), []byte("second"), "id", key); err != nil {
		t.Fatal(err)
	}
	if store.store["id"].encryptionAlgorithm != "AES_GCM" {
		t.Fatalf("algorithm %q", store.store["id"].encryptionAlgorithm)
	}
	got, err := store.Retrieve(context.Background(), "id", key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("second")) {
		t.Fatalf("got %q", got)
	}
}

func TestInMemoryTamperedCiphertext(t *testing.T) {
	store := newMem("AES_GCM")
	key, err := store.Store(context.Background(), []byte("hello"), "id")
	if err != nil {
		t.Fatal(err)
	}
	store.store["id"].data[len(store.store["id"].data)-1] ^= 0xff
	_, err = store.Retrieve(context.Background(), "id", key)
	if err == nil || errors.Is(err, ErrInvalidKey) || errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestInMemoryConcurrentDistinctIDs(t *testing.T) {
	store := newMem("AES_GCM")
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := strconv.Itoa(i)
			data := []byte("value-" + id)
			key, err := store.Store(context.Background(), data, id)
			if err != nil {
				t.Errorf("store %s: %v", id, err)
				return
			}
			got, err := store.Retrieve(context.Background(), id, key)
			if err != nil {
				t.Errorf("retrieve %s: %v", id, err)
				return
			}
			if !bytes.Equal(got, data) {
				t.Errorf("id %s got %q", id, got)
			}
		}(i)
	}
	wg.Wait()
}

func TestInMemoryConcurrentDuplicateID(t *testing.T) {
	store := newMem("AES_GCM")
	const n = 32
	var wg sync.WaitGroup
	keys := make(chan []byte, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, err := store.Store(context.Background(), []byte("v"), "same")
			if err != nil {
				errs <- err
				return
			}
			keys <- key
		}()
	}
	wg.Wait()
	close(keys)
	close(errs)

	var saved []byte
	success := 0
	for key := range keys {
		success++
		saved = key
	}
	conflicts := 0
	for err := range errs {
		if !errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("err = %v", err)
		}
		conflicts++
	}
	if success != 1 || conflicts != n-1 {
		t.Fatalf("success=%d conflicts=%d", success, conflicts)
	}
	got, err := store.Retrieve(context.Background(), "same", saved)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("v")) {
		t.Fatalf("got %q", got)
	}
}
