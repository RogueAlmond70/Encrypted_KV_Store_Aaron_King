package internal

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

func postgresDBName() string {
	if name := getEnv("POSTGRES_DB", ""); name != "" {
		return name
	}
	return getEnv("POSTGRES_DB_NAME", "")
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

type Config struct {
	PostgresHost        string
	PostgresPort        int
	PostgresUser        string
	PostgresPassword    string
	PostgresDbName      string
	PostgresSSLMode     string
	PostgresRetry       int
	PostgresRetryDelay  time.Duration
	DatastoreType       string
	EncryptionAlgorithm string
}

func LoadConfig() (*Config, error) {

	postgresPort, err := strconv.Atoi(getEnv("POSTGRES_PORT", "5432"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse POSTGRES_PORT: %w", err)
	}
	postgresRetry, err := strconv.Atoi(getEnv("POSTGRES_RETRY", "5"))
	if err != nil {
		return nil, fmt.Errorf("faied to parse POSTGRES_RETRY: %w", err)
	}
	postgresRetryDelay, err := time.ParseDuration(getEnv("POSTGRES_RETRY_DELAY", "5s"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse POSTGRES_RETRY_DELAY: %w", err)
	}

	return &Config{
		PostgresHost:        getEnv("POSTGRES_HOST", "localhost"),
		PostgresPort:        postgresPort,
		PostgresRetry:       postgresRetry,
		PostgresRetryDelay:  postgresRetryDelay,
		PostgresUser:        getEnv("POSTGRES_USER", ""),
		PostgresPassword:    getEnv("POSTGRES_PASSWORD", ""),
		PostgresDbName:      postgresDBName(),
		PostgresSSLMode:     getEnv("POSTGRES_SSL_MODE", "disable"),
		DatastoreType:       getEnv("DATASTORE_TYPE", "MEMORY"),
		EncryptionAlgorithm: getEnv("ENCRYPTION_ALGORITHM", "AES_GCM"),
	}, nil
}
