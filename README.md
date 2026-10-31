# attackmap-analyzer-go

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

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
uv tool install attackmap --with attackmap-analyzer-go \
  --index mlaify=https://pkg.mlaify.io/pypi/simple/ --index-strategy first-index
# or from source:
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
- **Method extraction**: gin uses uppercase methods (`r.GET`); chi/echo/fiber use title-case (`r.Get`), and chi also `r.Method("GET", "/x", h)`; gorilla/mux reads `.Methods("GET", http.MethodPost)` anywhere in the route's chain (`r.HandleFunc("/x", h).Methods(...)`, `r.Path("/x").Methods(...).HandlerFunc(h)`). net/http `HandleFunc` / `Handle` read Go 1.22 patterns: `"GET /items/{id}"` is `GET /items/{id}`, and a host (`"POST example.com/x"`) is kept as a `route_host:example.com` service hint quoting the registration. A pattern without a method is `ANY`.
- **Handlers**: any handler argument works — a name, a closure, or a wrapped handler (`authMW(h)`), for `HandleFunc` and `Handle` alike. Path literals can be interpreted (`"/x"`) or raw (`` `/x` ``) strings. `http.Handle("/", r)`, which serves a router built in the file, isn't a route of its own.
- **Group and sub-router prefixes**: a route's path is joined with the prefixes of the groups it's registered in: gin/echo/fiber `g := r.Group("/api")` (nested), chi `r.Route("/admin", func(r chi.Router) {...})` and `r.Route("/admin", adminRoutes)`, chi/fiber `r.Mount("/admin", sub)` / `r.Mount("/admin", adminRouter())` / `r.Mount("/admin", h.Routes())` (the function or method must be in the same file), fiber `app.Route("/x", func(api fiber.Router) {...})`, gorilla `api := r.PathPrefix("/api").Subrouter()`, and parameterless group closures of group-stack routers (gitea's `m.Group("/repos", func() {...})`). A prefix that isn't a literal (`e.Group(cfg.RootPath)`) stops the join: the path is relative to it. A router mounted twice, or mounted and used any other way, keeps its own paths and its auth is `unknown`, since it may be reachable without the parent's middleware. "Any other way" means anything but its own method calls (`sub.Get(...)`, `sub.Use(...)`) and the mount: passed as an argument (`http.ListenAndServe(addr, sub)`, `http.Serve(ln, sub)`, `handlers.LoggingHandler(w, sub)`), assigned (`srv.Handler = sub`), or `sub.ServeHTTP`. The same applies to a builder function or method used again (`apiRouter()`, `h.Routes()`). Occurrences in strings and comments, and fields of other values (`cfg.sub`), don't count. A path and method registered twice in a file with different auth is `unknown`: which registration serves the request depends on the framework. Chi `r.With(mw...).Route("/x", func(r chi.Router) {...})` / `.Group(...)` closures carry the prefix and the inline middleware. A derivation deeper than 32 levels keeps the route's own path. Prefixes set up in another function or file (`users.Register(v1.Group("/users"))`, gitea's `r.Mount("/api/v1", apiv1.Routes())`) aren't joined.
- **Route auth (AttackMap#256)**: each chi/gin/echo/fiber route carries `auth` (`required` / `anonymous` / `unknown`), `guards` and `guard_evidence`. Routers are tracked by variable within a file: constructors, `g := r.Group("/x", mw...)`, chi `r.With(mw...)` and `r.Group(func(r chi.Router) {...})` / `r.Route(...)` closures. A router passed in as a parameter is tracked within its function. `X.Use(mw)` applies to routes registered on `X` (or routers derived from it) *after* the call, and fiber's `Use("/prefix", mw)` only under the prefix. Route-local middleware is gin/fiber `r.POST(path, mw..., h)`, echo `e.POST(path, h, mw...)` and chi `r.With(mw).Post(...)`. A middleware is a guard when its name says it authenticates (`AuthRequired`, `jwtauth.Authenticator`, `middleware.JWT`, `echojwt.WithConfig`, `jwtware.New`, `keyauth.New`, `BasicAuth`, …). `jwtauth.Verifier` and `Optional*` middleware don't count. A guard's `Skipper` / `Next` / `Filter` that only compares the path with literals (`c.Path() == "/signup"`, `strings.HasPrefix(c.Path(), "/hooks/")`) makes the named routes `anonymous`. Any other skipper, or a config passed by variable, leaves them `unknown`. Group middleware carries over with the prefix: a guard on a group, sub-router or mounting router applies to the routes registered in it. gorilla `r.Use(mw)` applies to every route of `r` and its subrouters whenever they were registered, as gorilla runs it. A handler wrapped in auth middleware (`mux.Handle("/x", requireAuth(h))`, chi `r.Post("/x", authMW(h))`) is guarded when the called name (the last dotted segment) is middleware-shaped (`authMW`, `requireAuth`, `auth.Middleware`), or is `Handler` / `Wrap` on a middleware-named receiver (`jwtMiddleware.Handler`); `auth.LoginHandler(db)`, `authMW.LoginHandler(db)` and `oauthMiddleware.Callback(cb)` are handlers, not guards. The trailing middleware of a parameterless group closure (gitea's `m.Group("/x", func() {...}, mw)`) isn't read: it belongs to a project's own wrapper whose semantics can't be told from the name.
- **gRPC**: framework presence and `grpc.NewServer` entrypoint are detected. Per-service / per-method route extraction would require parsing `.proto` files — not yet supported.

## License

MIT
