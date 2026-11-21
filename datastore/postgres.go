package datastore

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/encryption"
	config "github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/internal"
	"github.com/RogueAlmond70/SpeedyDarts/internal"
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
	return &Postgres{
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

func (p *PostgresDatastore) Store(ctx context.Context, data []byte, id string) (string, error) {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		p.logger.Error("failed to store data for id", "id", id, "error", ctxErr)
		return "", fmt.Errorf("failed to store data for id: %w", ctxErr)
	}
	if id == "" {
		p.logger.Error("failed to store data", "missing id")
		return "", fmt.Errorf("failed to store data, missing id")
	}
	if data == nil {
		p.logger.Error("failed to store data", "nil data")
		return "", fmt.Errorf("failed to store data - nil data")
	}

	eKey, err := encryption.GenerateEncryptionKey()
	if err != nil {
		p.logger.Error("failed to store data for id", "id", id, "error", err)
		return "", fmt.Errorf("failed to store data: %w", err)
	}

	encryptedData, err := encryption.EncryptData(data, eKey)
	if err != nil {
		p.logger.Error("failed to store data for id", id, "error", err)
		return "", fmt.Errorf("failed to store data: %w", err)
	}

	// Call a method to update the database with the new data
	/*
		i.store[id] = Data{
			data:          encryptedData,
			encryptionKey: eKey,
		}
	*/

	return eKey, nil
}

func (p *PostgresDatastore) Retrieve(ctx context.Context, id string, key string) ([]byte, error) {
	// TODO: Implement me
	return nil, nil
}

func (p *PostgresDatastore) Update(ctx context.Context, data []byte, id string, key string) error {
	// TODO: Implement me
	return nil
}

func (p *PostgresDatastore) Delete(ctx context.Context, id string, key string) error {
	// TODO: Implement me
	return nil
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
