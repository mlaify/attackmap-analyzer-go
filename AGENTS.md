# AGENTS.md

## Project
This repository contains an AttackMap analyzer.

AttackMap analyzers live under:
- `github.com/mlaify`

This repo should implement one analyzer cleanly against the AttackMap core contract.

## Analyzer responsibilities
This analyzer should:
- detect whether it applies to a target repository
- emit structured signals
- remain heuristic but explainable

## Scope
Go ecosystem coverage:

- **Web frameworks**: net/http (stdlib), chi, gin, echo, fiber, gorilla/mux (routes + entrypoint markers); gRPC presence
- **Databases**: `database/sql` (postgres/mysql/sqlite drivers), gorm (driver-aware), sqlx, pgx/pgxpool, mongo-go-driver, go-redis, bbolt, AWS SDK (S3, DynamoDB)
- **Auth**: golang-jwt, x/oauth2, gorilla/sessions, casbin, x/crypto bcrypt/scrypt/argon2, go-chi/jwtauth, echo-jwt
- **HTTP clients**: net/http (`http.Get`/`http.Post`/`http.NewRequest`), go-resty, grequests
- **Secrets**: `os.Getenv`, `os.LookupEnv`, godotenv, viper.GetString
- **Service hints**: module name from `go.mod`

## Out of scope (for now)
- chi `r.Route("/api", ...)` / `r.Mount(...)` prefix nesting — inner routes extract, outer prefix is not joined.
- gRPC route extraction from `.proto` / generated code — only framework presence + server-startup are detected.
- Custom `http.Client` instances with URL constructed elsewhere — only literal-URL HTTP calls are picked up.

## Confidence policy
- Pattern hits on canonical import paths (`golang-jwt`, `x/oauth2`, `go-chi/jwtauth`, etc.) → ≥ 0.85
- Hash-style auth packages (bcrypt, scrypt, argon2 from `x/crypto`) → 0.9
- Keyword-only matches (`Authorization`, `Bearer`, `api_key`) → 0.6
- Secret env-var extractions → 0.85

## Testing
Tests write realistic Go snippets to `tmp_path` and assert on the resulting `ScanResult`. Each new extractor needs both:
- A positive test (signal fires on representative code).
- A negative test (signal does **not** fire on a look-alike — e.g., `(s *kv).Get("foo")` is not a chi route, `s.Get("api_key")` on a map type is not an HTTP call).

## Framework conflict resolution
When multiple frameworks could match in the same file:
- `gorilla/mux` + `net/http` → only `gorilla/mux` extracts routes (stdlib `HandleFunc` is wrapped, would double-count).
- `chi` + `echo` + `fiber` share a regex shape; framework markers in the file determine which extractor runs. If multiple framework markers appear, both extractors run — the dedup helper handles the overlap.
