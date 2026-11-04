# Changelog

All notable changes to `attackmap-analyzer-go` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-31

### Changed — packaging

- Released to the mlaify package index (https://pkg.mlaify.io/pypi/simple/). A `v*` tag now builds the wheel and sdist and attaches them to a GitHub release (`.github/workflows/release.yml`); the index picks them up within six hours.
- The `core` and `dev` extras require `attackmap>=0.6.0` from the index instead of AttackMap's git main.

### Fixed — JWT auth hints need a verifying call (#14, AttackMap#325)

- The `jwt` auth hint now comes only from `jwt.Parse(` / `jwt.ParseWithClaims(` / `.ParseWithClaims(`. Before, the import path (`golang-jwt/jwt`, `jwt-go`), `jwt.NewWithClaims` (signing) and `jwt.MapClaims` (a type) also counted. Core credits any auth hint near a route as that route's auth, so a file that only signs tokens made its routes look protected. `ParseUnverified` doesn't count.
- The same applies to `chi_jwtauth` and `echo_jwt`. They need `jwtauth.Verifier`/`Verify`/`VerifyToken`/`VerifyRequest`/`Authenticator`, or `echojwt.JWT`/`WithConfig` and `middleware.JWT`/`JWTWithConfig`. The import path and the `jwtauth.New` config no longer count.
- On gitea@eb3bc19: 9 → 4 `jwt` hints. All four remaining are on the `ParseWithClaims` line that core's `jwt_verified` also reports. The other five files only sign or generate tokens. Findings are unchanged.

### Added — route shapes and group prefixes (#3)

- **Go 1.22 ServeMux patterns.** `mux.HandleFunc("GET /items/{id}", h)` is `GET /items/{id}` (it was path `"GET /items/{id}"`, method `ANY`). A host (`"POST example.com/x"`) is kept as a `route_host:example.com` service hint quoting the registration; the route is `POST /x`.
- **`Handle` routes.** `mux.Handle(...)` / `http.Handle(...)` (FileServer, wrapped handlers) are emitted for net/http, and `r.Handle(...)` for gorilla. `http.Handle("/", r)` serving a router built in the same file isn't a route of its own.
- **gorilla/mux chains.** The handler can be anything (a closure, `authMW(h)`); the chain is read call by call with balanced-bracket scanning, so `r.HandleFunc("/b", func(...) {...}).Methods("POST")`, `r.Path("/e").Methods("GET").HandlerFunc(h)`, `r.PathPrefix("/static/").Handler(fs)` and `.Methods(http.MethodPut)` all work. The issue's fixture (`/a` named, `/b` closure, `/c` wrapped, `/d` Handle) went from 1 route to 4.
- **Group and sub-router prefixes are joined.** gin / echo / fiber `g := r.Group("/api")` (nested), chi `r.Route("/admin", func(r chi.Router) {...})` and `r.Route("/admin", adminRoutes)`, chi / fiber `r.Mount("/admin", sub | adminRouter() | h.Routes())` with the router built in the same file, fiber `app.Route(...)`, gorilla `r.PathPrefix("/api").Subrouter()`, and gitea-style parameterless `m.Group("/x", func() {...})` closures. A non-literal prefix stops the join; a router mounted twice, or mounted and used any other way, keeps its own paths and gets `unknown` auth. "Any other way" means anything but its own method calls and the mount: passed as an argument (`http.ListenAndServe(addr, sub)`, `http.Serve(ln, sub)`, `handlers.LoggingHandler(w, sub)`), assigned (`srv.Handler = sub`), `sub.ServeHTTP`, or its builder function called again. A route key registered twice with different auth is `unknown` (echo replaces the handler, chi prefers a static route over a mount). chi `r.With(mw...).Route(...)` / `.Group(...)` closures carry prefix and middleware. Past 32 levels of derivation a route keeps its own path.
- **Group middleware carries its auth.** A guard attached to a group, sub-router or mounting router (`admin.Use(AuthRequired())`, `e.Group("/admin", middleware.JWT(...))`, chi `r.Use(...)` before `r.Mount(...)`) applies to the routes in it, as before for same-router groups. gorilla `Use` applies to every route of the router and its subrouters regardless of order, as gorilla runs it. A handler wrapped in auth middleware whose called name is middleware-shaped (`requireAuth(h)`, `authMW(h)`, `auth.Middleware(h)`, or `Handler`/`Wrap` on a middleware-named receiver: `jwtMiddleware.Handler(h)`) is guarded for net/http, gorilla and chi routes. Middleware passed to a parameterless group closure is not read (its semantics belong to the project's own wrapper).
- chi `r.Method("GET", "/x", h)` / `MethodFunc` registrations, and raw-string (backtick) path literals everywhere.
- Router lookups climb enclosing blocks instead of walking sibling ones, so a function with hundreds of groups (gitea's `routers/web/web.go`) still resolves every route. Path literals are bounded to one line, and chains, mounts and derivation depth are bounded, so adversarial input stays linear (fuzz-tested). Mount targets are looked up through an offset index and a (name, method) table of declarations, and route dedup uses a fresh index per file; ratio tests (4x the input under 9x the time) cover many mounts, many same-named `Routes()` methods, many routes in one file and many files.

### Added — route-level auth (#7, AttackMap#256)

- **Routes carry their auth in the core contract.** `Route.auth` is `required`, `anonymous` or `unknown`, with `guards` naming the middleware and `guard_evidence` quoting the registration that attached it. AttackMap ≥ 0.6 trusts it over its own resolution, which can't read Go, and over the ±40-line auth-hint window. Older cores ignore the fields, and the existing auth hints are unchanged.
- **Resolved:** chi `r.Use(mw)`, `r.With(mw).Post(...)` and `r.Group(func(r chi.Router) {...})` / `r.Route("/x", ...)` closures; gin `r.Group("/x", mw...)`, `group.Use(mw)` and `r.POST(path, mw..., h)`; echo `e.Group("/x", mw...)`, `Use` and `e.POST(path, h, mw...)`; fiber `app.Use(mw)`, `app.Use("/prefix", mw)`, `app.Group("/x", mw...)` and `app.Post(path, mw..., h)`. `Use` applies only to routes registered after it. A router passed in as a parameter is tracked within its function.
- **Explicit opt-outs:** a guard's `Skipper` / `Next` / `Filter` that only compares the request path with literals makes the routes it names `anonymous`, at either app or group level. Any other skipper, a config passed by variable, `jwtauth.Verifier` alone and `Optional*` middleware leave routes `unknown`.
- `r.With(mw...).Post("/x", h)` registrations in chi files are now extracted as routes. They were missed before.
- Brackets are matched in one cached pass per file, arguments are split by jumping over nested closures, and binding lookups, `Use` lists and derivation depth are bounded, so adversarial input stays linear.

### Changed

- **License metadata uses an SPDX expression (PEP 639).** `license = "MIT"` and `license-files = ["LICENSE"]` replace the deprecated `license = {text = "MIT"}` table, and the `License ::` classifier (which setuptools ≥ 77 rejects next to an expression) is gone. The build backend floor is now `setuptools>=77` (mlaify/AttackMap#259).
- **Import the analyzer contract from `attackmap.sdk` directly; `contracts.py` is gone.** It only re-exported SDK types (and aliased `AnalyzerProtocol` as `AttackMapAnalyzerProtocol`), and its four copy-pasted variants drifted across the plugins (mlaify/AttackMap#259).
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

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-go/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mlaify/attackmap-analyzer-go/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-go/releases/tag/v0.1.0
