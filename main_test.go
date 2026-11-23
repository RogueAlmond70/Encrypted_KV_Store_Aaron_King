package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/datastore"
)

func TestWriteStoreError(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		body   string
	}{
		{"invalid input", datastore.ErrInvalidInput, http.StatusBadRequest, "invalid request\n"},
		{"wrapped invalid input", fmt.Errorf("store: %w", datastore.ErrInvalidInput), http.StatusBadRequest, "invalid request\n"},
		{"not found", datastore.ErrNotFound, http.StatusNotFound, "entry not found\n"},
		{"invalid key", datastore.ErrInvalidKey, http.StatusUnauthorized, "encryption key incorrect\n"},
		{"already exists", datastore.ErrAlreadyExists, http.StatusConflict, "entry already exists\n"},
		{"other", errors.New("disk failed"), http.StatusInternalServerError, "failed to handle request\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeStoreError(rec, tc.err)
			if rec.Code != tc.status {
				t.Fatalf("status %d", rec.Code)
			}
			if rec.Body.String() != tc.body {
				t.Fatalf("body %q", rec.Body.String())
			}
		})
	}
}

func TestStatusRecorderCapturesTheFirstStatus(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	rec.WriteHeader(http.StatusCreated)
	rec.WriteHeader(http.StatusOK)
	if rec.status != http.StatusCreated {
		t.Fatalf("status %d", rec.status)
	}

	implicit := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	if _, err := implicit.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if implicit.status != http.StatusOK {
		t.Fatalf("status %d", implicit.status)
	}
}

func TestLoadProjectEnvMissingFile(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := loadProjectEnv(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadProjectEnvOverridesProcessEnv(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("KV_STORE_TEST_FROM_DOTENV=from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KV_STORE_TEST_FROM_DOTENV", "from-process")
	t.Chdir(dir)
	if err := loadProjectEnv(); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("KV_STORE_TEST_FROM_DOTENV"); got != "from-file" {
		t.Fatalf("value %q", got)
	}
}

func TestLoadProjectEnvRejectsUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".env"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if err := loadProjectEnv(); err == nil {
		t.Fatal("expected .env directory to fail")
	}
}
