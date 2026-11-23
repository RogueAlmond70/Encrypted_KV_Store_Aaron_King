package datastore

import (
	"context"
)

type DataStore interface {
	Store(ctx context.Context, data []byte, id string) ([]byte, error)
	Retrieve(ctx context.Context, id string, key []byte) ([]byte, error)
	Update(ctx context.Context, data []byte, id string, key []byte) error
	Delete(ctx context.Context, id string, key []byte) error
}

type Data struct {
	data                []byte
	encryptionKey       []byte
	encryptionAlgorithm string
}
