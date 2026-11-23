package internal

import (
	"os"
	"testing"
	"time"
)

func clearConfigEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"POSTGRES_HOST",
		"POSTGRES_PORT",
		"POSTGRES_USER",
		"POSTGRES_PASSWORD",
		"POSTGRES_DB",
		"POSTGRES_DB_NAME",
		"POSTGRES_SSL_MODE",
		"POSTGRES_RETRY",
		"POSTGRES_RETRY_DELAY",
		"DATASTORE_TYPE",
		"ENCRYPTION_ALGORITHM",
	}
	saved := make(map[string]*string, len(keys))
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			copied := value
			saved[key] = &copied
		}
		os.Unsetenv(key)
	}
	t.Cleanup(func() {
		for _, key := range keys {
			if saved[key] == nil {
				os.Unsetenv(key)
				continue
			}
			os.Setenv(key, *saved[key])
		}
	})
}

func TestLoadConfigDefaults(t *testing.T) {
	clearConfigEnv(t)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PostgresHost != "localhost" || cfg.PostgresPort != 5432 {
		t.Fatalf("host %s port %d", cfg.PostgresHost, cfg.PostgresPort)
	}
	if cfg.PostgresUser != "" || cfg.PostgresPassword != "" || cfg.PostgresDbName != "" {
		t.Fatalf("user %q password %q db %q", cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresDbName)
	}
	if cfg.PostgresSSLMode != "disable" {
		t.Fatalf("ssl %q", cfg.PostgresSSLMode)
	}
	if cfg.PostgresRetry != 5 || cfg.PostgresRetryDelay != 5*time.Second {
		t.Fatalf("retry %d delay %s", cfg.PostgresRetry, cfg.PostgresRetryDelay)
	}
	if cfg.DatastoreType != "MEMORY" || cfg.EncryptionAlgorithm != "AES_GCM" {
		t.Fatalf("store %q algorithm %q", cfg.DatastoreType, cfg.EncryptionAlgorithm)
	}
}

func TestLoadConfigReadsEnvironment(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("POSTGRES_HOST", "db.internal")
	t.Setenv("POSTGRES_PORT", "5433")
	t.Setenv("POSTGRES_USER", "kv")
	t.Setenv("POSTGRES_PASSWORD", "secret")
	t.Setenv("POSTGRES_DB", "entries")
	t.Setenv("POSTGRES_DB_NAME", "ignored")
	t.Setenv("POSTGRES_SSL_MODE", "require")
	t.Setenv("POSTGRES_RETRY", "2")
	t.Setenv("POSTGRES_RETRY_DELAY", "250ms")
	t.Setenv("DATASTORE_TYPE", "POSTGRES")
	t.Setenv("ENCRYPTION_ALGORITHM", "CHACHA20_POLY1305")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PostgresHost != "db.internal" || cfg.PostgresPort != 5433 {
		t.Fatalf("host %s port %d", cfg.PostgresHost, cfg.PostgresPort)
	}
	if cfg.PostgresUser != "kv" || cfg.PostgresPassword != "secret" || cfg.PostgresDbName != "entries" {
		t.Fatalf("user %q password %q db %q", cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresDbName)
	}
	if cfg.PostgresSSLMode != "require" || cfg.PostgresRetry != 2 || cfg.PostgresRetryDelay != 250*time.Millisecond {
		t.Fatalf("ssl %q retry %d delay %s", cfg.PostgresSSLMode, cfg.PostgresRetry, cfg.PostgresRetryDelay)
	}
	if cfg.DatastoreType != "POSTGRES" || cfg.EncryptionAlgorithm != "CHACHA20_POLY1305" {
		t.Fatalf("store %q algorithm %q", cfg.DatastoreType, cfg.EncryptionAlgorithm)
	}
}

func TestLoadConfigDBNameFallback(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("POSTGRES_DB_NAME", "from-name")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PostgresDbName != "from-name" {
		t.Fatalf("db %q", cfg.PostgresDbName)
	}

	t.Setenv("POSTGRES_DB", "")
	cfg, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PostgresDbName != "from-name" {
		t.Fatalf("empty POSTGRES_DB hid POSTGRES_DB_NAME, db %q", cfg.PostgresDbName)
	}
}

func TestLoadConfigRejectsBadDurationsAndPorts(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("POSTGRES_PORT", "nope")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("accepted a bad port")
	}

	clearConfigEnv(t)
	t.Setenv("POSTGRES_RETRY", "nope")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("accepted a bad retry count")
	}

	clearConfigEnv(t)
	t.Setenv("POSTGRES_RETRY_DELAY", "nope")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("accepted a bad retry delay")
	}
}
