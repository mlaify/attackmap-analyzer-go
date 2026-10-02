# Changelog

All notable changes to `attackmap-analyzer-go` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — route-level auth (#7, AttackMap#256)

- **Routes carry their auth in the core contract.** `Route.auth` is `required`, `anonymous` or `unknown`, with `guards` naming the middleware and `guard_evidence` quoting the registration that attached it. AttackMap ≥ 0.6 trusts it over its own resolution, which can't read Go, and over the ±40-line auth-hint window. Older cores ignore the fields, and the existing auth hints are unchanged.
- **Resolved:** chi `r.Use(mw)`, `r.With(mw).Post(...)` and `r.Group(func(r chi.Router) {...})` / `r.Route("/x", ...)` closures; gin `r.Group("/x", mw...)`, `group.Use(mw)` and `r.POST(path, mw..., h)`; echo `e.Group("/x", mw...)`, `Use` and `e.POST(path, h, mw...)`; fiber `app.Use(mw)`, `app.Use("/prefix", mw)`, `app.Group("/x", mw...)` and `app.Post(path, mw..., h)`. `Use` applies only to routes registered after it. A router passed in as a parameter is tracked within its function.
- **Explicit opt-outs:** a guard's `Skipper` / `Next` / `Filter` that only compares the request path with literals makes the routes it names `anonymous`, at either app or group level. Any other skipper, a config passed by variable, `jwtauth.Verifier` alone and `Optional*` middleware leave routes `unknown`.
- `r.With(mw...).Post("/x", h)` registrations in chi files are now extracted as routes. They were missed before.
- Brackets are matched in one cached pass per file, arguments are split by jumping over nested closures, and binding lookups, `Use` lists and derivation depth are bounded, so adversarial input stays linear.

### Changed

- Walk and read the repo with the shared `attackmap.sdk.fs` helpers
  (`iter_repo_files`, `read_source`, `rel`, `line_of`) instead of a private
  `rglob` + `SKIP_DIRS` walk ([mlaify/AttackMap#253](https://github.com/mlaify/AttackMap/issues/253)).
  Skip dirs are now the SDK `DEFAULT_SKIP_DIRS` (a superset of the old list; it also skips `out/`, `target/`, `.venv/` and AttackMap output dirs).

### Fixed

- Title-case `.Get("...")` lookups in chi and fiber files are no longer reported
  as routes (`req.Header.Get("Authorization")`, `q.Get("id")`, `viper.Get(...)`,
  fiber `c.Get("X-Api-Key")`). A chi/fiber registration now needs a path literal
  starting with `/` (or fiber's `*`) followed by a handler argument, on a
  receiver that isn't a request accessor or the request context
  ([#2](https://github.com/mlaify/attackmap-analyzer-go/issues/2)).
- `*_test.go` files and `testdata/` directories are no longer scanned, so
  `httptest` registrations stop showing up as production routes. The old
  `SKIP_SUFFIXES` constant was declared but never applied and is removed. Set
  `ATTACKMAP_INCLUDE_TESTS=1` to scan test code. Directories the core treats as
  test code (`test/`, `tests/`, `e2e/`, `fixtures/`, ...) are skipped too
  ([#2](https://github.com/mlaify/attackmap-analyzer-go/issues/2)).
- A repo checked out under a directory named like a skip dir (e.g. `/build/...`,
  `.../out/...`) was silently skipped entirely; skip dirs are now matched only
  inside the repo.
- Symlinked files pointing outside the repo are no longer analyzed.
- An unreadable file no longer raises out of `analyze()`, and cp1252/latin-1
  sources are analyzed instead of dropped. `files_scanned` counts only files
  that were actually read.
- `detect()` stops at the first `go.mod` or `.go` file and prunes skipped directories instead of walking all of them.

## [0.1.0] - 2026-06-04

### Added

- Initial public release. Go ecosystem analyzer plugin for AttackMap (net/http, chi, gin, echo, fiber, gorilla/mux; database/sql, gorm, sqlx, pgx; golang-jwt; resty).
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-go/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-go/releases/tag/v0.1.0
