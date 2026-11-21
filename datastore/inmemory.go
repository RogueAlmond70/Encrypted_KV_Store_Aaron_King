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
}

func (i *InMemoryDatastore) Store(ctx context.Context, data []byte, id string) (string, error) {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		i.logger.Error("failed to store data for id", "id", id, "error", ctxErr)
		return "", fmt.Errorf("failed to store data for id: %w", ctxErr)
	}
	if id == "" {
		i.logger.Error("failed to store data", "missing id")
		return "", fmt.Errorf("failed to store data, missing id")
	}
	if data == nil {
		i.logger.Error("failed to store data", "nil data")
		return "", fmt.Errorf("failed to store data - nil data")
	}

	eKey, err := encryption.GenerateEncryptionKey()
	if err != nil {
		i.logger.Error("failed to store data for id", "id", id, "error", err)
		return "", fmt.Errorf("failed to store data: %w", err)
	}

	encryptedData, err := encryption.EncryptData(data, eKey)
	if err != nil {
		i.logger.Error("failed to store data for id", id, "error", err)
		return "", fmt.Errorf("failed to store data: %w", err)
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	if i.store == nil {
		i.store = make(map[string]Data)
	}

	i.store[id] = Data{
		data:          encryptedData,
		encryptionKey: eKey,
	}

	return eKey, nil
}

func (i *InMemoryDatastore) Retrieve(ctx context.Context, id string, key string) ([]byte, error) {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		i.logger.Error("failed to retrieve data for id", "id", id, "error", ctxErr)
		return nil, fmt.Errorf("failed to retrieve data for id: %w", ctxErr)
	}
	if id == "" {
		i.logger.Error("failed to retrieve data", "missing id")
		return nil, fmt.Errorf("failed to retrieve data, missing id")
	}
	if key == "" {
		i.logger.Error("failed to retrieve data", "missing key")
		return nil, fmt.Errorf("failed to retrieve data, missing key")
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	requestedData, ok := i.store[id]
	if !ok {
		i.logger.Error("failed to retrieve data", "no data found for id", "id", id)
		return nil, fmt.Errorf("failed to retrieve data for key provided")
	}

	// If using AES-GCM authentication, an incorrect key will be rejected during decryption anyway, this is belt and braces.
	if key != requestedData.encryptionKey {
		i.logger.Error("failed to retrieve data for id", id, "key does not match")
		return nil, fmt.Errorf("failed to retrieve data - incorrect key")
	}

	decryptedData, err := encryption.DecryptData(requestedData.data, key)
	if err != nil {
		i.logger.Error("failed to retrieve data", "error", err)
		return nil, fmt.Errorf("failed to retrieve data: %w", err)
	}

	return decryptedData, nil
}

func (i *InMemoryDatastore) Update(ctx context.Context, data []byte, id string, key string) error {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		i.logger.Error("failed to update data for id", "id", id, "error", ctxErr)
		return fmt.Errorf("failed to update data for id: %w", ctxErr)
	}
	if id == "" {
		i.logger.Error("failed to update data", "missing id")
		return fmt.Errorf("failed to update data, missing id")
	}
	if key == "" {
		i.logger.Error("failed to update data", "missing key")
		return fmt.Errorf("failed to update data, missing key")
	}

	if data == nil {
		i.logger.Error("failed to update data", "nil data")
		return fmt.Errorf("failed to update data - nil data")
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	entry, ok := i.store[id]
	if !ok {
		i.logger.Error("failed to update data for id", "id", id, "id not found in map")
		return fmt.Errorf("failed to update data - id not found in map")
	}
	// Checking the supplied key is the correct key for this id, the id being the map key.
	// So does the the encryption key in the entry stored for that map key(the id) match the encryption key provided as a param

	if entry.encryptionKey != key { // TODO: Store a hash of the key instead
		i.logger.Error("failed to update data for id", "id", id, "encryption key incorrect")
		return fmt.Errorf("failed to update data - encryption key incorrect")
	}

	encryptedData, err := encryption.EncryptData(data, key)
	if err != nil {
		i.logger.Error("failed to update data for id", id, "error", err)
		return fmt.Errorf("failed to update data: %w", err)
	}

	updatedData := Data{
		data:          encryptedData,
		encryptionKey: key, // may be able to remove this depending on the authentication method we go with
	}
	i.store[id] = updatedData
	return nil
}

func (i *InMemoryDatastore) Delete(ctx context.Context, id string, key string) error {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		i.logger.Error("failed to delete data for id", "id", id, "error", ctxErr)
		return fmt.Errorf("failed to delete data for id: %w", ctxErr)
	}
	if id == "" {
		i.logger.Error("failed to delete data", "missing id")
		return fmt.Errorf("failed to delete data, missing id")
	}
	if key == "" {
		i.logger.Error("failed to delete data", "missing key")
		return fmt.Errorf("failed to delete data, missing key")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	entry, ok := i.store[id]
	if !ok {
		i.logger.Error("failed to delete data for id", "id", id, "id not found in map")
		return fmt.Errorf("failed to delete data - id not found in map")
	}

	if entry.encryptionKey != key { // TODO: Store a hash of the key instead
		i.logger.Error("failed to delete data for id", "id", id, "encryption key incorrect")
		return fmt.Errorf("failed to delete data - encryption key incorrect")
	}

	delete(i.store, id)

	return nil
}
