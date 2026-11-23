-- +goose Up

CREATE TABLE key_value_entries (
    id TEXT PRIMARY KEY,
    encrypted_data BYTEA NOT NULL,
    key_hash BYTEA NOT NULL,
    encryption_algorithm TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose Down

DROP TABLE key_value_entries;
