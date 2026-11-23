package datastore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/encryption"
	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/internal"
	"github.com/jackc/pgx/v5/pgconn"
)

func newMockStore(t *testing.T, algorithm string) (*PostgresDatastore, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := NewPostgresDatastore(discard(), db, internal.Config{EncryptionAlgorithm: algorithm})
	return store, mock
}

func checkMock(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func seal(t *testing.T, plain []byte, algorithm string) (key, ciphertext, hash []byte) {
	t.Helper()
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	var err error
	ciphertext, err = encryption.EncryptData(plain, key, "id", discard(), algorithm)
	if err != nil {
		t.Fatal(err)
	}
	hash, err = encryption.KeyHash(key, discard())
	if err != nil {
		t.Fatal(err)
	}
	return key, ciphertext, hash
}

func valueBytes(v driver.Value) ([]byte, bool) {
	switch b := v.(type) {
	case []byte:
		return b, true
	case string:
		return []byte(b), true
	default:
		return nil, false
	}
}

type exactBytes []byte

func (e exactBytes) Match(v driver.Value) bool {
	b, ok := valueBytes(v)
	return ok && string(b) == string(e)
}

type minCipherLen int

func (n minCipherLen) Match(v driver.Value) bool {
	b, ok := valueBytes(v)
	return ok && len(b) > int(n)
}

func TestPostgresRejectsInvalidInputBeforeQuery(t *testing.T) {
	store := NewPostgresDatastore(discard(), nil, internal.Config{})
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

func TestPostgresCancelledContext(t *testing.T) {
	store := NewPostgresDatastore(discard(), nil, internal.Config{EncryptionAlgorithm: "AES_GCM"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := store.Store(ctx, []byte("a"), "id"); !errors.Is(err, context.Canceled) {
		t.Fatalf("store: %v", err)
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

func TestPostgresStoreInvalidAlgorithm(t *testing.T) {
	store := NewPostgresDatastore(discard(), nil, internal.Config{EncryptionAlgorithm: "ROT13"})
	_, err := store.Store(context.Background(), []byte("a"), "id")
	if !errors.Is(err, encryption.ErrInvalidAlgorithm) {
		t.Fatalf("err = %v", err)
	}
}

func TestPostgresStoreInsert(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	mock.ExpectExec("INSERT INTO key_value_entries").
		WithArgs("id", minCipherLen(len("hello")), exactLen(32), "AES_GCM").
		WillReturnResult(sqlmock.NewResult(0, 1))

	key, err := store.Store(context.Background(), []byte("hello"), "id")
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key length %d", len(key))
	}
	checkMock(t, mock)
}

type exactLen int

func (n exactLen) Match(v driver.Value) bool {
	b, ok := valueBytes(v)
	return ok && len(b) == int(n)
}

func TestPostgresStoreAlreadyExists(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	mock.ExpectExec("INSERT INTO key_value_entries").
		WillReturnError(&pgconn.PgError{Code: "23505"})

	_, err := store.Store(context.Background(), []byte("hello"), "id")
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("err = %v", err)
	}
	checkMock(t, mock)
}

func TestPostgresStoreOtherDatabaseError(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	mock.ExpectExec("INSERT INTO key_value_entries").
		WillReturnError(&pgconn.PgError{Code: "23502"})

	_, err := store.Store(context.Background(), []byte("hello"), "id")
	if err == nil || errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("err = %v", err)
	}
	checkMock(t, mock)
}

func TestPostgresRetrieve(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	plain := []byte("hello")
	key, ciphertext, hash := seal(t, plain, "AES_GCM")
	mock.ExpectQuery("SELECT encrypted_data, key_hash, encryption_algorithm").
		WithArgs("id").
		WillReturnRows(sqlmock.NewRows([]string{"encrypted_data", "key_hash", "encryption_algorithm"}).
			AddRow(ciphertext, hash, "AES_GCM"))

	got, err := store.Retrieve(context.Background(), "id", key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("got %q", got)
	}
	checkMock(t, mock)
}

func TestPostgresRetrieveNotFound(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	mock.ExpectQuery("SELECT encrypted_data, key_hash, encryption_algorithm").
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)

	_, err := store.Retrieve(context.Background(), "missing", []byte("key"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	checkMock(t, mock)
}

func TestPostgresRetrieveQueryError(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	mock.ExpectQuery("SELECT encrypted_data, key_hash, encryption_algorithm").
		WithArgs("id").
		WillReturnError(errors.New("db down"))

	_, err := store.Retrieve(context.Background(), "id", []byte("key"))
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	checkMock(t, mock)
}

func TestPostgresRetrieveWrongKey(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	_, _, hash := seal(t, []byte("hello"), "AES_GCM")
	mock.ExpectQuery("SELECT encrypted_data, key_hash, encryption_algorithm").
		WithArgs("id").
		WillReturnRows(sqlmock.NewRows([]string{"encrypted_data", "key_hash", "encryption_algorithm"}).
			AddRow([]byte("ciphertext"), hash, "AES_GCM"))

	_, err := store.Retrieve(context.Background(), "id", []byte("wrong-key"))
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("err = %v", err)
	}
	checkMock(t, mock)
}

func TestPostgresRetrieveTamperedCiphertext(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	key, ciphertext, hash := seal(t, []byte("hello"), "AES_GCM")
	ciphertext[len(ciphertext)-1] ^= 0xff
	mock.ExpectQuery("SELECT encrypted_data, key_hash, encryption_algorithm").
		WithArgs("id").
		WillReturnRows(sqlmock.NewRows([]string{"encrypted_data", "key_hash", "encryption_algorithm"}).
			AddRow(ciphertext, hash, "AES_GCM"))

	_, err := store.Retrieve(context.Background(), "id", key)
	if err == nil || errors.Is(err, ErrInvalidKey) || errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	checkMock(t, mock)
}

func TestPostgresUpdate(t *testing.T) {
	store, mock := newMockStore(t, "CHACHA20_POLY1305")
	key, _, hash := seal(t, []byte("old"), "AES_GCM")
	mock.ExpectBegin()
	mock.ExpectQuery("(?s)SELECT key_hash, encryption_algorithm.*FOR UPDATE").
		WithArgs("id").
		WillReturnRows(sqlmock.NewRows([]string{"key_hash", "encryption_algorithm"}).
			AddRow(hash, "AES_GCM"))
	mock.ExpectExec("UPDATE key_value_entries").
		WithArgs(minCipherLen(len("new")), exactBytes(hash), "AES_GCM", "id").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := store.Update(context.Background(), []byte("new"), "id", key); err != nil {
		t.Fatal(err)
	}
	checkMock(t, mock)
}

func TestPostgresUpdateNotFound(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	mock.ExpectBegin()
	mock.ExpectQuery("(?s)SELECT key_hash, encryption_algorithm.*FOR UPDATE").
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	err := store.Update(context.Background(), []byte("new"), "missing", []byte("key"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	checkMock(t, mock)
}

func TestPostgresUpdateWrongKey(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	_, _, hash := seal(t, []byte("old"), "AES_GCM")
	mock.ExpectBegin()
	mock.ExpectQuery("(?s)SELECT key_hash, encryption_algorithm.*FOR UPDATE").
		WithArgs("id").
		WillReturnRows(sqlmock.NewRows([]string{"key_hash", "encryption_algorithm"}).
			AddRow(hash, "AES_GCM"))
	mock.ExpectRollback()

	err := store.Update(context.Background(), []byte("new"), "id", []byte("wrong-key"))
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("err = %v", err)
	}
	checkMock(t, mock)
}

func TestPostgresUpdateNoRows(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	key, _, hash := seal(t, []byte("old"), "AES_GCM")
	mock.ExpectBegin()
	mock.ExpectQuery("(?s)SELECT key_hash, encryption_algorithm.*FOR UPDATE").
		WithArgs("id").
		WillReturnRows(sqlmock.NewRows([]string{"key_hash", "encryption_algorithm"}).
			AddRow(hash, "AES_GCM"))
	mock.ExpectExec("UPDATE key_value_entries").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err := store.Update(context.Background(), []byte("new"), "id", key)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	checkMock(t, mock)
}

func TestPostgresUpdateRowsAffectedError(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	key, _, hash := seal(t, []byte("old"), "AES_GCM")
	mock.ExpectBegin()
	mock.ExpectQuery("(?s)SELECT key_hash, encryption_algorithm.*FOR UPDATE").
		WithArgs("id").
		WillReturnRows(sqlmock.NewRows([]string{"key_hash", "encryption_algorithm"}).
			AddRow(hash, "AES_GCM"))
	mock.ExpectExec("UPDATE key_value_entries").
		WillReturnResult(sqlmock.NewErrorResult(errors.New("rows")))
	mock.ExpectRollback()

	err := store.Update(context.Background(), []byte("new"), "id", key)
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	checkMock(t, mock)
}

func TestPostgresUpdateBeginAndCommitErrors(t *testing.T) {
	t.Run("begin", func(t *testing.T) {
		store, mock := newMockStore(t, "AES_GCM")
		mock.ExpectBegin().WillReturnError(errors.New("no tx"))
		err := store.Update(context.Background(), []byte("new"), "id", []byte("key"))
		if err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
		checkMock(t, mock)
	})

	t.Run("commit", func(t *testing.T) {
		store, mock := newMockStore(t, "AES_GCM")
		key, _, hash := seal(t, []byte("old"), "AES_GCM")
		mock.ExpectBegin()
		mock.ExpectQuery("(?s)SELECT key_hash, encryption_algorithm.*FOR UPDATE").
			WithArgs("id").
			WillReturnRows(sqlmock.NewRows([]string{"key_hash", "encryption_algorithm"}).
				AddRow(hash, "AES_GCM"))
		mock.ExpectExec("UPDATE key_value_entries").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit().WillReturnError(errors.New("commit"))

		err := store.Update(context.Background(), []byte("new"), "id", key)
		if err == nil {
			t.Fatal("commit error was ignored")
		}
		checkMock(t, mock)
	})
}

func TestPostgresDelete(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	key, _, hash := seal(t, []byte("hello"), "AES_GCM")
	mock.ExpectBegin()
	mock.ExpectQuery("(?s)SELECT key_hash\\s+FROM key_value_entries.*FOR UPDATE").
		WithArgs("id").
		WillReturnRows(sqlmock.NewRows([]string{"key_hash"}).AddRow(hash))
	mock.ExpectExec("DELETE FROM key_value_entries").
		WithArgs("id").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := store.Delete(context.Background(), "id", key); err != nil {
		t.Fatal(err)
	}
	checkMock(t, mock)
}

func TestPostgresDeleteNotFound(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	mock.ExpectBegin()
	mock.ExpectQuery("(?s)SELECT key_hash\\s+FROM key_value_entries.*FOR UPDATE").
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	err := store.Delete(context.Background(), "missing", []byte("key"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	checkMock(t, mock)
}

func TestPostgresDeleteWrongKey(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	_, _, hash := seal(t, []byte("hello"), "AES_GCM")
	mock.ExpectBegin()
	mock.ExpectQuery("(?s)SELECT key_hash\\s+FROM key_value_entries.*FOR UPDATE").
		WithArgs("id").
		WillReturnRows(sqlmock.NewRows([]string{"key_hash"}).AddRow(hash))
	mock.ExpectRollback()

	err := store.Delete(context.Background(), "id", []byte("wrong-key"))
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("err = %v", err)
	}
	checkMock(t, mock)
}

func TestPostgresDeleteNoRowsAndExecError(t *testing.T) {
	t.Run("no rows", func(t *testing.T) {
		store, mock := newMockStore(t, "AES_GCM")
		key, _, hash := seal(t, []byte("hello"), "AES_GCM")
		mock.ExpectBegin()
		mock.ExpectQuery("(?s)SELECT key_hash\\s+FROM key_value_entries.*FOR UPDATE").
			WithArgs("id").
			WillReturnRows(sqlmock.NewRows([]string{"key_hash"}).AddRow(hash))
		mock.ExpectExec("DELETE FROM key_value_entries").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectRollback()

		err := store.Delete(context.Background(), "id", key)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
		checkMock(t, mock)
	})

	t.Run("exec", func(t *testing.T) {
		store, mock := newMockStore(t, "AES_GCM")
		key, _, hash := seal(t, []byte("hello"), "AES_GCM")
		mock.ExpectBegin()
		mock.ExpectQuery("(?s)SELECT key_hash\\s+FROM key_value_entries.*FOR UPDATE").
			WithArgs("id").
			WillReturnRows(sqlmock.NewRows([]string{"key_hash"}).AddRow(hash))
		mock.ExpectExec("DELETE FROM key_value_entries").
			WillReturnError(errors.New("delete failed"))
		mock.ExpectRollback()

		err := store.Delete(context.Background(), "id", key)
		if err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
		checkMock(t, mock)
	})
}

func TestPostgresMigrateReportsDatabaseFailure(t *testing.T) {
	store, mock := newMockStore(t, "AES_GCM")
	mock.ExpectQuery(".*").WillReturnError(errors.New("no schema"))
	err := store.Migrate()
	if err == nil {
		t.Fatal("expected migration to fail")
	}
}

func TestGetPostgresConnStr(t *testing.T) {
	raw := getPostgresConnStr(&internal.Config{
		PostgresHost:     "db.example",
		PostgresPort:     5433,
		PostgresUser:     "user name",
		PostgresPassword: "p@ss/word",
		PostgresDbName:   "kv",
		PostgresSSLMode:  "require",
	})
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "postgres" || u.Host != "db.example:5433" || u.Path != "/kv" {
		t.Fatalf("url %s", raw)
	}
	if u.User.Username() != "user name" {
		t.Fatalf("user %q", u.User.Username())
	}
	password, ok := u.User.Password()
	if !ok || password != "p@ss/word" {
		t.Fatalf("password %q", password)
	}
	if u.Query().Get("sslmode") != "require" {
		t.Fatalf("sslmode %q", u.Query().Get("sslmode"))
	}
}

func TestConnectDBWithRetryStopsAfterRefusedConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	_, err = ConnectDBWithRetry(internal.Config{
		PostgresHost:       "127.0.0.1",
		PostgresPort:       port,
		PostgresUser:       "kv",
		PostgresPassword:   "kv",
		PostgresDbName:     "kv",
		PostgresSSLMode:    "disable",
		PostgresRetry:      2,
		PostgresRetryDelay: time.Millisecond,
	}, discard())
	if err == nil {
		t.Fatal("connected to a closed port")
	}

	_, err = ConnectDBWithRetry(internal.Config{
		PostgresHost:       "127.0.0.1",
		PostgresPort:       port,
		PostgresUser:       "kv",
		PostgresPassword:   "kv",
		PostgresDbName:     "kv",
		PostgresSSLMode:    "disable",
		PostgresRetry:      0,
		PostgresRetryDelay: time.Millisecond,
	}, discard())
	if err == nil {
		t.Fatal("retry of 0 should still fail against a closed port")
	}
}
