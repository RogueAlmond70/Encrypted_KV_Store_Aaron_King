package datastore

import (
	"context"
)

type DataStore interface {
	Store(ctx context.Context, data []byte, id string) (string, error)
	Retrieve(ctx context.Context, id string, key string) ([]byte, error)
	Update(ctx context.Context, data []byte, id string, key string) error
	Delete(ctx context.Context, id string, key string) error
}

type Data struct {
	data          []byte
	encryptionKey string
}
