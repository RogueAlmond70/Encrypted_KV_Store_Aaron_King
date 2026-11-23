package datastore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/encryption"
	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/internal"
	config "github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/internal"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type PostgresDatastore struct {
	logger internal.Logger
	db     *sql.DB
	cfg    config.Config
}

func NewPostgresDatastore(logger internal.Logger, sqldb *sql.DB, cfg config.Config) *PostgresDatastore {
	return &PostgresDatastore{
		logger: logger,
		db:     sqldb,
		cfg:    cfg,
	}
}

func (p *PostgresDatastore) Migrate() error { // make this a function, it doesn't need to be a method right now
	goose.SetBaseFS(migrationFiles)

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("setting goose dialect: %w", err)
	}

	if err := goose.Up(p.db, "migrations"); err != nil {
		return fmt.Errorf("running database migrations: %w", err)
	}

	p.logger.Info("Database migrations applied successfully")
	return nil
}

func (p *PostgresDatastore) Store(ctx context.Context, data []byte, id string) ([]byte, error) {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		p.logger.Error("failed to store data for id", "id", id, "error", ctxErr)
		return nil, fmt.Errorf("failed to store data for id: %w", ctxErr)
	}
	if id == "" {
		p.logger.Error("failed to store data", "missing id")
		return nil, fmt.Errorf("failed to store data, missing id: %w", ErrInvalidInput)
	}
	if data == nil {
		p.logger.Error("failed to store data", "nil data")
		return nil, fmt.Errorf("failed to store data - nil data: %w", ErrInvalidInput)
	}

	eKey, err := encryption.GenerateEncryptionKey(p.logger)
	if err != nil {
		p.logger.Error("failed to store data for id", "id", id, "error", err)
		return nil, fmt.Errorf("failed to store data: %w", err)
	}

	encryptedData, err := encryption.EncryptData(data, eKey, id, p.logger, p.cfg.EncryptionAlgorithm)
	if err != nil {
		p.logger.Error("failed to store data for id", "id", id, "error", err)
		return nil, fmt.Errorf("failed to store data: %w", err)
	}

	hashedKey, err := encryption.KeyHash(eKey, p.logger)
	if err != nil {
		p.logger.Error("failed to store data for id", "id", id, "error", err)
		return nil, fmt.Errorf("failed to store data: %w", err)
	}

	_, err = p.db.ExecContext(ctx, `
		INSERT INTO key_value_entries (id, encrypted_data, key_hash, encryption_algorithm)
		VALUES ($1, $2, $3, $4)`,
		id, encryptedData, hashedKey, p.cfg.EncryptionAlgorithm,
	)
	if err != nil {
		if isUniqueViolation(err) {
			p.logger.Error("failed to store data", "reason", "id already exists", "id", id)
			return nil, fmt.Errorf("failed to store data - id already exists: %w", ErrAlreadyExists)
		}
		p.logger.Error("failed to store data for id", "id", id, "error", err)
		return nil, fmt.Errorf("failed to store data: %w", err)
	}

	return eKey, nil
}

func (p *PostgresDatastore) Retrieve(ctx context.Context, id string, key []byte) ([]byte, error) {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		p.logger.Error("failed to retrieve data for id", "id", id, "error", ctxErr)
		return nil, fmt.Errorf("failed to retrieve data for id: %w", ctxErr)
	}
	if id == "" {
		p.logger.Error("failed to retrieve data", "missing id")
		return nil, fmt.Errorf("failed to retrieve data, missing id: %w", ErrInvalidInput)
	}
	if key == nil {
		p.logger.Error("failed to retrieve data", "missing key")
		return nil, fmt.Errorf("failed to retrieve data, missing key: %w", ErrInvalidInput)
	}

	var encryptedData, keyHash []byte
	var algorithm string
	err := p.db.QueryRowContext(ctx, `
		SELECT encrypted_data, key_hash, encryption_algorithm
		FROM key_value_entries
		WHERE id = $1`, id).Scan(&encryptedData, &keyHash, &algorithm)
	if errors.Is(err, sql.ErrNoRows) {
		p.logger.Error("failed to retrieve data", "no data found for id", "id", id)
		return nil, fmt.Errorf("failed to retrieve data for key provided: %w", ErrNotFound)
	}
	if err != nil {
		p.logger.Error("failed to retrieve data for id", "id", id, "error", err)
		return nil, fmt.Errorf("failed to retrieve data: %w", err)
	}

	verified, err := encryption.HashVerify(key, keyHash, p.logger)
	if !verified {
		p.logger.Error("failed to retrieve data for id", "id", id, "reason", "encryption key incorrect")
		return nil, fmt.Errorf("failed to retrieve data - encryption key incorrect: %w", ErrInvalidKey)
	}
	if err != nil {
		p.logger.Error("failed to retrieve data for id", "id", id, "error", err)
		return nil, fmt.Errorf("failed to retrieve data: %w", err)
	}

	decryptedData, err := encryption.DecryptData(encryptedData, key, id, p.logger, algorithm)
	if err != nil {
		p.logger.Error("failed to retrieve data", "error", err)
		return nil, fmt.Errorf("failed to retrieve data: %w", err)
	}

	return decryptedData, nil
}

func (p *PostgresDatastore) Update(ctx context.Context, data []byte, id string, key []byte) error {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		p.logger.Error("failed to update data for id", "id", id, "error", ctxErr)
		return fmt.Errorf("failed to update data for id: %w", ctxErr)
	}
	if id == "" {
		p.logger.Error("failed to update data", "missing id")
		return fmt.Errorf("failed to update data, missing id: %w", ErrInvalidInput)
	}
	if key == nil {
		p.logger.Error("failed to update data", "missing key")
		return fmt.Errorf("failed to update data, missing key: %w", ErrInvalidInput)
	}
	if data == nil {
		p.logger.Error("failed to update data", "nil data")
		return fmt.Errorf("failed to update data - nil data: %w", ErrInvalidInput)
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		p.logger.Error("failed to update data for id", "id", id, "error", err)
		return fmt.Errorf("failed to update data: %w", err)
	}
	defer tx.Rollback()

	var keyHash []byte
	var algorithm string
	err = tx.QueryRowContext(ctx, `
		SELECT key_hash, encryption_algorithm
		FROM key_value_entries
		WHERE id = $1
		FOR UPDATE`, id).Scan(&keyHash, &algorithm)
	if errors.Is(err, sql.ErrNoRows) {
		p.logger.Error("failed to update data for id", "id", id, "id not found")
		return fmt.Errorf("failed to update data - id not found: %w", ErrNotFound)
	}
	if err != nil {
		p.logger.Error("failed to update data for id", "id", id, "error", err)
		return fmt.Errorf("failed to update data: %w", err)
	}

	verified, err := encryption.HashVerify(key, keyHash, p.logger)
	if !verified {
		p.logger.Error("failed to update data for id", "id", id, "reason", "encryption key incorrect")
		return fmt.Errorf("failed to update data - encryption key incorrect: %w", ErrInvalidKey)
	}
	if err != nil {
		p.logger.Error("failed to update data for id", "id", id, "error", err)
		return fmt.Errorf("failed to update data: %w", err)
	}

	encryptedData, err := encryption.EncryptData(data, key, id, p.logger, algorithm)
	if err != nil {
		p.logger.Error("failed to update data for id", "id", id, "error", err)
		return fmt.Errorf("failed to update data: %w", err)
	}

	hashedKey, err := encryption.KeyHash(key, p.logger)
	if err != nil {
		p.logger.Error("failed to update data for id", "id", id, "error", err)
		return fmt.Errorf("failed to update data: %w", err)
	}

	result, err := tx.ExecContext(ctx, `
		UPDATE key_value_entries
		SET encrypted_data = $1, key_hash = $2, encryption_algorithm = $3, updated_at = NOW()
		WHERE id = $4`,
		encryptedData, hashedKey, algorithm, id,
	)
	if err != nil {
		p.logger.Error("failed to update data for id", "id", id, "error", err)
		return fmt.Errorf("failed to update data: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		p.logger.Error("failed to update data for id", "id", id, "error", err)
		return fmt.Errorf("failed to update data: %w", err)
	}
	if affected == 0 {
		p.logger.Error("failed to update data for id", "id", id, "id not found")
		return fmt.Errorf("failed to update data - id not found: %w", ErrNotFound)
	}

	if err := tx.Commit(); err != nil {
		p.logger.Error("failed to update data for id", "id", id, "error", err)
		return fmt.Errorf("failed to update data: %w", err)
	}
	return nil
}

func (p *PostgresDatastore) Delete(ctx context.Context, id string, key []byte) error {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		p.logger.Error("failed to delete data for id", "id", id, "error", ctxErr)
		return fmt.Errorf("failed to delete data for id: %w", ctxErr)
	}
	if id == "" {
		p.logger.Error("failed to delete data", "missing id")
		return fmt.Errorf("failed to delete data, missing id: %w", ErrInvalidInput)
	}
	if key == nil {
		p.logger.Error("failed to delete data", "missing key")
		return fmt.Errorf("failed to delete data, missing key: %w", ErrInvalidInput)
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		p.logger.Error("failed to delete data for id", "id", id, "error", err)
		return fmt.Errorf("failed to delete data: %w", err)
	}
	defer tx.Rollback()

	var keyHash []byte
	err = tx.QueryRowContext(ctx, `
		SELECT key_hash
		FROM key_value_entries
		WHERE id = $1
		FOR UPDATE`, id).Scan(&keyHash)
	if errors.Is(err, sql.ErrNoRows) {
		p.logger.Error("failed to delete data for id", "id", id, "id not found")
		return fmt.Errorf("failed to delete data - id not found: %w", ErrNotFound)
	}
	if err != nil {
		p.logger.Error("failed to delete data for id", "id", id, "error", err)
		return fmt.Errorf("failed to delete data: %w", err)
	}

	verified, err := encryption.HashVerify(key, keyHash, p.logger)
	if !verified {
		p.logger.Error("failed to delete data for id", "id", id, "reason", "encryption key incorrect")
		return fmt.Errorf("failed to delete data - encryption key incorrect: %w", ErrInvalidKey)
	}
	if err != nil {
		p.logger.Error("failed to delete data for id", "id", id, "error", err)
		return fmt.Errorf("failed to delete data: %w", err)
	}

	result, err := tx.ExecContext(ctx, `DELETE FROM key_value_entries WHERE id = $1`, id)
	if err != nil {
		p.logger.Error("failed to delete data for id", "id", id, "error", err)
		return fmt.Errorf("failed to delete data: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		p.logger.Error("failed to delete data for id", "id", id, "error", err)
		return fmt.Errorf("failed to delete data: %w", err)
	}
	if affected == 0 {
		p.logger.Error("failed to delete data for id", "id", id, "id not found")
		return fmt.Errorf("failed to delete data - id not found: %w", ErrNotFound)
	}

	if err := tx.Commit(); err != nil {
		p.logger.Error("failed to delete data for id", "id", id, "error", err)
		return fmt.Errorf("failed to delete data: %w", err)
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func getPostgresConnStr(cfg *config.Config) string {
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.PostgresUser, cfg.PostgresPassword),
		Host:   net.JoinHostPort(cfg.PostgresHost, strconv.Itoa(cfg.PostgresPort)),
		Path:   "/" + cfg.PostgresDbName,
	}
	query := u.Query()
	query.Set("sslmode", cfg.PostgresSSLMode)
	u.RawQuery = query.Encode()
	return u.String()
}

func ConnectDB(cfg config.Config) (*sql.DB, error) {
	connStr := getPostgresConnStr(&cfg)
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return nil, fmt.Errorf("error connecting to database: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("error checking database connection: %w", err)
	}
	return db, nil
}

func ConnectDBWithRetry(cfg config.Config, logger internal.Logger) (*sql.DB, error) {
	var db *sql.DB
	var err error
	if cfg.PostgresRetry < 1 {
		cfg.PostgresRetry = 5
	}
	logger.Info(
		"Connecting to database",
		"host", cfg.PostgresHost,
		"port", cfg.PostgresPort,
		"user", cfg.PostgresUser,
		"database", cfg.PostgresDbName,
	)
	for i := 0; i < cfg.PostgresRetry; i++ {
		db, err = ConnectDB(cfg)
		if err == nil {
			return db, nil
		}
		logger.Warn("Failed to connect to DB", "attempt", i+1, "max_attempts", cfg.PostgresRetry)

		if i < cfg.PostgresRetry-1 {
			time.Sleep(cfg.PostgresRetryDelay)
		}
	}
	return nil, fmt.Errorf("failed to connect to database after %d attempts: %w", cfg.PostgresRetry, err)
}
