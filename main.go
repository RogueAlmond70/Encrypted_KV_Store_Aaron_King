package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/datastore"
	config "github.com/RogueAlmond70/Encryped_KV_Store_Aaron_King/internal"
	"github.com/joho/godotenv"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if err := loadProjectEnv(); err != nil {
		logger.Error("failed to load .env", "error", err)
		os.Exit(1)
	}

	config, err := config.LoadConfig()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	var keyvalue datastore.DataStore

	switch config.DatastoreType {
	case "POSTGRES":
		db, err := datastore.ConnectDBWithRetry(*config, logger)

		if err != nil {
			logger.Error("failed to setup postgres datastore", "error", err)
			os.Exit(1) // TODO: Check exit code
		}
		defer db.Close()

		pg := datastore.NewPostgresDatastore(logger, db, *config)
		err = pg.Migrate()
		if err != nil {
			logger.Error("failed to setup postgres datastore", "migration failed", "error", err)
			os.Exit(1)
		}
		keyvalue = pg
		logger.Info("POSTGRES datastore configured and running")

	case "MEMORY":
		keyvalue = datastore.NewInMemoryDatastore(logger, *config)
		logger.Info("In Memory datastore configured and running")
	default:
		logger.Error("failed to setup datastore", "unknown datastore type", "type", config.DatastoreType)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	type StoreRequest struct {
		Data []byte `json:"data"`
	}

	type UpdateRequest struct {
		Data []byte `json:"data"`
		Key  string `json:"key"`
	}

	mux.HandleFunc("/yoti/{id}", func(w http.ResponseWriter, r *http.Request) {
		var (
			storerequest  StoreRequest
			updaterequest UpdateRequest
		)
		switch r.Method {
		case http.MethodPost:
			defer r.Body.Close()
			err := json.NewDecoder(r.Body).Decode(&storerequest)
			if err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			id := r.PathValue("id")
			encryptionKey, err := keyvalue.Store(r.Context(), storerequest.Data, id)
			if err != nil {
				http.Error(w, "failed to handle request", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)

			json.NewEncoder(w).Encode(map[string]string{
				"key": base64.StdEncoding.EncodeToString(encryptionKey),
			})

		case http.MethodGet:
			id := r.PathValue("id")
			key, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Encryption-Key"))
			if err != nil {
				http.Error(w, "failed to handle request", http.StatusBadRequest)
				return
			}
			data, err := keyvalue.Retrieve(r.Context(), id, key)
			if err != nil {
				http.Error(w, "failed to handle request", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			json.NewEncoder(w).Encode(map[string][]byte{
				"data": data,
			})

		case http.MethodPut:
			defer r.Body.Close()
			id := r.PathValue("id")

			err := json.NewDecoder(r.Body).Decode(&updaterequest)
			if err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			data := updaterequest.Data
			key, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Encryption-Key"))
			if err != nil {
				http.Error(w, "failed to handle request", http.StatusBadRequest)
				return
			}
			err = keyvalue.Update(r.Context(), data, id, key)
			if err != nil {
				http.Error(w, "failed to handle request", http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusNoContent)

		case http.MethodDelete:
			defer r.Body.Close()
			id := r.PathValue("id")

			key, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Encryption-Key"))
			if err != nil {
				http.Error(w, "failed to handle request", http.StatusBadRequest)
				return
			}

			err = keyvalue.Delete(r.Context(), id, key)
			if err != nil {
				http.Error(w, "failed to handle request", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}

	})
	http.ListenAndServe(":8080", mux)
}

// loadProjectEnv applies the repository .env over any inherited environment.
// A missing file is ignored so a deployed process can rely on real environment variables.
func loadProjectEnv() error {
	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("finding working directory: %w", err)
	}

	for {
		envPath := filepath.Join(dir, ".env")
		if _, statErr := os.Stat(envPath); statErr == nil {
			if err := godotenv.Overload(envPath); err != nil {
				return fmt.Errorf("loading %s: %w", envPath, err)
			}
			return nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}
