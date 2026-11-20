package datastore

type DataStore interface {
	Store(data []byte, id string) (string, error)
	Retrieve(id string, key string) ([]byte, error)
	Update(data []byte, id string, key string) error
	Delete(id string, key string) error
}
