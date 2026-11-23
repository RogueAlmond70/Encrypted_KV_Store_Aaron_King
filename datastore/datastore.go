package datastore

import (
	"context"
	"errors"
)

var (
	ErrInvalidInput  = errors.New("invalid input")
	ErrNotFound      = errors.New("entry not found")
	ErrInvalidKey    = errors.New("encryption key incorrect")
	ErrAlreadyExists = errors.New("entry already exists")
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
