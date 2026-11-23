# Encrypted key-value store

HTTP service that stores `[]byte` values under an id. Each entry gets its own 32-byte key. The service keeps a SHA-256 hash of that key and the ciphertext. The raw key is returned once, on store, and must be sent back to retrieve, update, or delete.

## Run

`docker compose up --build` starts one server on port `8080` with the in-memory store.

To use Postgres instead, start the database as well. On Windows PowerShell:

```powershell
$env:DATASTORE_TYPE = "POSTGRES"
docker compose --profile postgres up --build
```

The server still listens on port `8080`. The database `kv` is created by the Postgres image, with user `kv` and password `kv`. On startup the server applies the goose migration in `datastore/migrations`, which creates `key_value_entries` (`id`, `encrypted_data`, `key_hash`, `encryption_algorithm`, timestamps). Postgres data is kept in the `pgdata` volume. Restarting an in-memory server drops its entries.

The server uses `AES_GCM`, set by `ENCRYPTION_ALGORITHM` on the `server` service in `docker-compose.yml`. Change that value to `AES_GCM_SIV` or `CHACHA20_POLY1305`, then run Compose again. The algorithm is stored on the entry, so a request decrypts with the value saved when that entry was stored. A new value applies only to entries stored after the change.

On Windows PowerShell, call `curl.exe`. `curl` is an alias for `Invoke-WebRequest`.

## Store, then retrieve

`data` in JSON is standard base64, because the field is `[]byte`. The string below is the bytes `hello`.

```sh
curl -s -X POST http://localhost:8080/yoti/demo \
  -H "Content-Type: application/json" \
  -d "{\"data\":\"aGVsbG8=\"}"
```

`201` response:

```json
{"key":"<standard base64 of the 32-byte key>"}
```

Pass that key back in `X-Encryption-Key`:

```sh
curl -s http://localhost:8080/yoti/demo \
  -H "X-Encryption-Key: <key from the store response>"
```

`200` response. `data` is standard base64 of the original bytes (`aGVsbG8=` for `hello`):

```json
{"data":"aGVsbG8="}
```

## API

One route, `/yoti/{id}`.

| Method | Body | Key header | Success |
| --- | --- | --- | --- |
| `POST` | `{"data":"<base64>"}` | none | `201` `{"key":"<base64>"}` |
| `GET` | none | `X-Encryption-Key` | `200` `{"data":"<base64>"}` |
| `PUT` | `{"data":"<base64>"}` | `X-Encryption-Key` | `204` |
| `DELETE` | none | `X-Encryption-Key` | `204` |

`PUT` and `DELETE` use the header for the key. An id is required. `data` must be present (`null` is rejected).

| Status | Meaning |
| --- | --- |
| `400` | Missing id, missing data, bad JSON, or a key header that is not standard base64 |
| `401` | Id exists and the key does not match |
| `404` | Id is not in the store |
| `409` | `POST` for an id that already exists |
| `405` | Method other than the four above |
| `500` | Anything else. The body is `failed to handle request` |


