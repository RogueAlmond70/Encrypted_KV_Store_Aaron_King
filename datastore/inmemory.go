package datastore

import (
	"context"
	"fmt"
	"sync"

	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/encryption"
	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/internal"
)

type InMemoryDatastore struct {
	store  (map[string]Data)
	logger internal.Logger
	mu     sync.Mutex
	cfg    internal.Config
}

func NewInMemoryDatastore(logger internal.Logger, cfg internal.Config) *InMemoryDatastore {
	store := make(map[string]Data)
	return &InMemoryDatastore{
		store:  store,
		logger: logger,
		mu:     sync.Mutex{},
		cfg:    cfg,
	}
}

func (i *InMemoryDatastore) Store(ctx context.Context, data []byte, id string) ([]byte, error) {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		i.logger.Error("failed to store data for id", "id", id, "error", ctxErr)
		return nil, fmt.Errorf("failed to store data for id: %w", ctxErr)
	}
	if id == "" {
		i.logger.Error("failed to store data", "missing id")
		return nil, fmt.Errorf("failed to store data, missing id: %w", ErrInvalidInput)
	}
	if data == nil {
		i.logger.Error("failed to store data", "nil data")
		return nil, fmt.Errorf("failed to store data - nil data: %w", ErrInvalidInput)
	}
	// check for existing id
	i.mu.Lock()
	defer i.mu.Unlock()

	_, ok := i.store[id]
	if ok {
		i.logger.Error("failed to store data", "reason", "id already exists")
		return nil, fmt.Errorf("failed to store data - id already exists: %w", ErrAlreadyExists)
	}

	key, err := encryption.GenerateEncryptionKey(i.logger)
	if err != nil {
		i.logger.Error("failed to store data for id", "id", id, "error", err)
		return nil, fmt.Errorf("failed to store data: %w", err)
	}

	encryptedData, err := encryption.EncryptData(data, key, id, i.logger, i.cfg.EncryptionAlgorithm)
	if err != nil {
		i.logger.Error("failed to store data for id", id, "error", err)
		return nil, fmt.Errorf("failed to store data: %w", err)
	}

	if i.store == nil {
		i.store = make(map[string]Data)
	}

	hashedKey, err := encryption.KeyHash(key, i.logger)
	if err != nil {
		i.logger.Error("failed to store data for id", "id", id, "error", err)
		return nil, fmt.Errorf("failed to store data: %w", err)
	}

	i.store[id] = Data{
		data:                encryptedData,
		encryptionKey:       hashedKey,
		encryptionAlgorithm: i.cfg.EncryptionAlgorithm,
	}

	return key, nil
}

func (i *InMemoryDatastore) Retrieve(ctx context.Context, id string, key []byte) ([]byte, error) {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		i.logger.Error("failed to retrieve data for id", "id", id, "error", ctxErr)
		return nil, fmt.Errorf("failed to retrieve data for id: %w", ctxErr)
	}
	if id == "" {
		i.logger.Error("failed to retrieve data", "missing id")
		return nil, fmt.Errorf("failed to retrieve data, missing id: %w", ErrInvalidInput)
	}
	if key == nil {
		i.logger.Error("failed to retrieve data", "missing key")
		return nil, fmt.Errorf("failed to retrieve data, missing key: %w", ErrInvalidInput)
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	requestedData, ok := i.store[id]
	if !ok {
		i.logger.Error("failed to retrieve data", "no data found for id", "id", id)
		return nil, fmt.Errorf("failed to retrieve data for key provided: %w", ErrNotFound)
	}

	verified, err := encryption.HashVerify(key, requestedData.encryptionKey, i.logger)
	if !verified {
		i.logger.Error("failed to retrieve data for id", "id", id, "reason", "encryption key incorrect")
		return nil, fmt.Errorf("failed to retrieve data - encryption key incorrect: %w", ErrInvalidKey)
	}
	if err != nil {
		i.logger.Error("failed to retrieve data for id", "id", id, "error", err)
		return nil, fmt.Errorf("failed to retrieve data: %w", err)
	}

	decryptedData, err := encryption.DecryptData(requestedData.data, key, id, i.logger, requestedData.encryptionAlgorithm)
	if err != nil {
		i.logger.Error("failed to retrieve data", "error", err)
		return nil, fmt.Errorf("failed to retrieve data: %w", err)
	}

	return decryptedData, nil
}

func (i *InMemoryDatastore) Update(ctx context.Context, data []byte, id string, key []byte) error {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		i.logger.Error("failed to update data for id", "id", id, "error", ctxErr)
		return fmt.Errorf("failed to update data for id: %w", ctxErr)
	}
	if id == "" {
		i.logger.Error("failed to update data", "missing id")
		return fmt.Errorf("failed to update data, missing id: %w", ErrInvalidInput)
	}
	if key == nil {
		i.logger.Error("failed to update data", "missing key")
		return fmt.Errorf("failed to update data, missing key: %w", ErrInvalidInput)
	}

	if data == nil {
		i.logger.Error("failed to update data", "nil data")
		return fmt.Errorf("failed to update data - nil data: %w", ErrInvalidInput)
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	entry, ok := i.store[id]
	if !ok {
		i.logger.Error("failed to update data for id", "id", id, "id not found in map")
		return fmt.Errorf("failed to update data - id not found in map: %w", ErrNotFound)
	}

	verified, err := encryption.HashVerify(key, entry.encryptionKey, i.logger)
	if !verified {
		i.logger.Error("failed to update data for id", "id", id, "reason", "encryption key incorrect")
		return fmt.Errorf("failed to update data - encryption key incorrect: %w", ErrInvalidKey)
	}
	if err != nil {
		i.logger.Error("failed to update data for id", "id", id, "error", err)
		return fmt.Errorf("failed to update data: %w", err)
	}

	encryptedData, err := encryption.EncryptData(data, key, id, i.logger, entry.encryptionAlgorithm)
	if err != nil {
		i.logger.Error("failed to update data for id", id, "error", err)
		return fmt.Errorf("failed to update data: %w", err)
	}

	hashedKey, err := encryption.KeyHash(key, i.logger)
	if err != nil {
		i.logger.Error("failed to update data for id", "id", id, "error", err)
		return fmt.Errorf("failed to update data: %w", err)
	}

	updatedData := Data{
		data:                encryptedData,
		encryptionKey:       hashedKey,
		encryptionAlgorithm: entry.encryptionAlgorithm,
	}
	i.store[id] = updatedData
	return nil
}

func (i *InMemoryDatastore) Delete(ctx context.Context, id string, key []byte) error {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		i.logger.Error("failed to delete data for id", "id", id, "error", ctxErr)
		return fmt.Errorf("failed to delete data for id: %w", ctxErr)
	}
	if id == "" {
		i.logger.Error("failed to delete data", "missing id")
		return fmt.Errorf("failed to delete data, missing id: %w", ErrInvalidInput)
	}
	if key == nil {
		i.logger.Error("failed to delete data", "missing key")
		return fmt.Errorf("failed to delete data, missing key: %w", ErrInvalidInput)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	entry, ok := i.store[id]
	if !ok {
		i.logger.Error("failed to delete data for id", "id", id, "id not found in map")
		return fmt.Errorf("failed to delete data - id not found in map: %w", ErrNotFound)
	}

	verified, err := encryption.HashVerify(key, entry.encryptionKey, i.logger)
	if !verified {
		i.logger.Error("failed to delete data for id", "id", id, "reason", "encryption key incorrect")
		return fmt.Errorf("failed to delete data - encryption key incorrect: %w", ErrInvalidKey)
	}
	if err != nil {
		i.logger.Error("failed to delete data for id", "id", id, "error", err)
		return fmt.Errorf("failed to delete data: %w", err)
	}

	delete(i.store, id)

	return nil
}
