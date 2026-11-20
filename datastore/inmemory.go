package datastore

import (
	"sync"

	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/internal"
)

type InMemoryDatastore struct {
	store  (map[string][]byte)
	mu     sync.Mutex
	logger internal.Logger
}

func (i *InMemoryDatastore) Store(data []byte, id string) (string, error) {

	return "", nil
}

func (i *InMemoryDatastore) Retrieve(id string, key string) ([]byte, error) {

	return nil, nil
}

func (i *InMemoryDatastore) Update(data []byte, id string, key string) error {
	return nil
}

func (i *InMemoryDatastore) Delete(id string, key string) error {

	return nil
}
