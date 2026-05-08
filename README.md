# attackmap-analyzer-go

Go ecosystem analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

This analyzer extracts structured signals from Go modules and workspaces:

- **Web frameworks** — net/http (stdlib), chi, gin, echo, fiber, gorilla/mux (route + entrypoint extraction)
- **Databases** — `database/sql` (Postgres / MySQL / SQLite drivers), gorm (with driver-aware kind inference), sqlx, pgx, mongo-go-driver, go-redis, bbolt, AWS SDK (S3, DynamoDB)
- **Auth packages** — golang-jwt, golang.org/x/oauth2, gorilla/sessions, casbin, x/crypto/bcrypt / scrypt / argon2, go-chi/jwtauth, echo-jwt
- **HTTP clients (external calls)** — net/http (`http.Get` / `http.Post` / `http.NewRequest`), go-resty, grequests
- **Secrets** — `os.Getenv`, `os.LookupEnv`, `godotenv`, `viper.GetString`
- **Service hints** — module name extracted from `go.mod`

All emissions populate AttackMap's Signal v2 fields (line numbers, evidence snippets, confidence scores) so downstream insights can cite `path/to/file.go:NN`.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-go.git
```

The analyzer is auto-discovered by AttackMap via the `attackmap.analyzers` entry-point group.

## Usage with AttackMap

```bash
# Auto-discovered when installed:
attackmap analyze /path/to/go/repo

# Or invoke explicitly:
attackmap analyze /path/to/go/repo --module go
```

## Detection

`detect()` returns true when any of the following are present, ignoring `vendor/`, `.git/`, `node_modules/`, `dist/`, and `build/`:

- A `go.mod` or `go.sum` at the repository root, or anywhere in the tree
- One or more `.go` files in the tree

## Coverage notes

- **Framework-aware route extraction**: chi/echo/fiber all use the same title-case verb pattern (`r.Get(...)`, `r.Post(...)`). To avoid mis-attributing generic `.Get(...)` calls (e.g., on a map type) as routes, the analyzer only fires those extractors when the file *also* contains a recognizable framework marker (`go-chi/chi` import, `chi.NewRouter(`, `labstack/echo`, `echo.New(`, etc.).
- **gorilla/mux + net/http**: when both are detected in the same file, only the gorilla extractor runs. The stdlib `HandleFunc` extractor would otherwise double-count the same routes.
- **Method extraction**: gin uses uppercase methods (`r.GET`); chi/echo/fiber use title-case (`r.Get`); gorilla/mux chains `.Methods("GET", "POST")` after `HandleFunc`. All three shapes are supported. `http.HandleFunc` has no method information, so those routes are emitted with method `ANY`.
- **chi `Route()` / `Mount()` prefix nesting**: routes inside `r.Route("/api", func(r chi.Router) { ... })` are extracted but the outer `/api` prefix is not currently joined to the inner paths. Roadmap.
- **gRPC**: framework presence and `grpc.NewServer` entrypoint are detected. Per-service / per-method route extraction would require parsing `.proto` files — not yet supported.

## License

MIT
