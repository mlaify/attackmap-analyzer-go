"""Tests for the GoAnalyzer plugin.

Each test writes a realistic Go snippet into tmp_path and asserts on the
resulting ScanResult. Line-number assertions verify the Signal v2 plumbing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap_analyzer_go import GoAnalyzer


# ---------- detect() ----------


def test_detect_picks_up_go_mod(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/demo\n\ngo 1.22\n", encoding="utf-8")
    assert GoAnalyzer().detect(tmp_path) is True


def test_detect_picks_up_bare_go_files(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text("package main\n\nfunc main() {}\n", encoding="utf-8")
    assert GoAnalyzer().detect(tmp_path) is True


def test_detect_skips_vendor_dir(tmp_path: Path) -> None:
    vendor = tmp_path / "vendor" / "github.com" / "x"
    vendor.mkdir(parents=True)
    (vendor / "leftover.go").write_text("package x\n", encoding="utf-8")
    assert GoAnalyzer().detect(tmp_path) is False


def test_detect_returns_false_for_empty_dir(tmp_path: Path) -> None:
    assert GoAnalyzer().detect(tmp_path) is False


def test_detect_returns_false_for_missing_path(tmp_path: Path) -> None:
    assert GoAnalyzer().detect(tmp_path / "nope") is False


# ---------- Routes: gin ----------


def test_gin_route_extraction_with_uppercase_methods(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        'package main\n'
        '\n'
        'import "github.com/gin-gonic/gin"\n'
        '\n'
        'func main() {\n'
        '    r := gin.Default()\n'
        '    r.GET("/users", listUsers)\n'
        '    r.POST("/users", createUser)\n'
        '    r.DELETE("/users/:id", deleteUser)\n'
        '    r.Run(":8080")\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    pairs = sorted({(r.path, r.method) for r in result.routes})
    assert ("/users", "GET") in pairs
    assert ("/users", "POST") in pairs
    assert ("/users/:id", "DELETE") in pairs

    get_route = next(r for r in result.routes if r.method == "GET" and r.path == "/users")
    assert get_route.line == 7  # the r.GET line


# ---------- Routes: chi ----------


def test_chi_route_extraction(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        'package main\n'
        '\n'
        'import "github.com/go-chi/chi/v5"\n'
        '\n'
        'func setup() {\n'
        '    r := chi.NewRouter()\n'
        '    r.Get("/health", healthHandler)\n'
        '    r.Post("/login", loginHandler)\n'
        '    r.Patch("/users/{id}", updateUser)\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    pairs = sorted({(r.path, r.method) for r in result.routes})
    assert ("/health", "GET") in pairs
    assert ("/login", "POST") in pairs
    assert ("/users/{id}", "PATCH") in pairs


def test_chi_routes_not_extracted_without_chi_marker(tmp_path: Path) -> None:
    """Generic title-case .Get(...) calls in non-chi files must not produce routes."""
    (tmp_path / "main.go").write_text(
        'package main\n'
        '\n'
        'import "fmt"\n'
        '\n'
        'type fakeMap struct{ m map[string]string }\n'
        'func (f *fakeMap) Get(k string) string { return f.m[k] }\n'
        '\n'
        'func main() {\n'
        '    var f fakeMap\n'
        '    fmt.Println(f.Get("/fake"))\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    assert result.routes == []


# ---------- Routes: echo ----------


def test_echo_route_extraction(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        'package main\n'
        '\n'
        'import "github.com/labstack/echo/v4"\n'
        '\n'
        'func main() {\n'
        '    e := echo.New()\n'
        '    e.GET("/api/users", listUsers)\n'
        '    e.POST("/api/users", createUser)\n'
        '    e.Start(":1323")\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    # Echo uses uppercase verbs at runtime; either pattern (gin's or chi/echo's) catches them.
    pairs = sorted({(r.path, r.method) for r in result.routes})
    assert ("/api/users", "GET") in pairs
    assert ("/api/users", "POST") in pairs


# ---------- Routes: fiber ----------


def test_fiber_route_extraction(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        'package main\n'
        '\n'
        'import "github.com/gofiber/fiber/v2"\n'
        '\n'
        'func main() {\n'
        '    app := fiber.New()\n'
        '    app.Get("/", indexHandler)\n'
        '    app.Post("/upload", uploadHandler)\n'
        '    app.Listen(":3000")\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/", "GET") in pairs
    assert ("/upload", "POST") in pairs


# ---------- Routes: gorilla/mux ----------


def test_gorilla_mux_route_with_methods_chain(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        'package main\n'
        '\n'
        'import "github.com/gorilla/mux"\n'
        '\n'
        'func setupRoutes() {\n'
        '    r := mux.NewRouter()\n'
        '    r.HandleFunc("/api/items", itemsHandler).Methods("GET", "POST")\n'
        '    r.HandleFunc("/admin/users/{id}", adminHandler).Methods("DELETE")\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    pairs = sorted({(r.path, r.method) for r in result.routes})
    assert ("/api/items", "GET") in pairs
    assert ("/api/items", "POST") in pairs
    assert ("/admin/users/{id}", "DELETE") in pairs


def test_gorilla_mux_route_without_methods_chain_emits_any(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        'package main\n'
        '\n'
        'import "github.com/gorilla/mux"\n'
        '\n'
        'func setup() {\n'
        '    r := mux.NewRouter()\n'
        '    r.HandleFunc("/probe", probeHandler)\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    assert any(r.path == "/probe" and r.method == "ANY" for r in result.routes)


# ---------- Routes: net/http stdlib ----------


def test_net_http_handlefunc_emits_any_route(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        'package main\n'
        '\n'
        'import "net/http"\n'
        '\n'
        'func main() {\n'
        '    http.HandleFunc("/health", healthHandler)\n'
        '    http.ListenAndServe(":8080", nil)\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    assert any(r.path == "/health" and r.method == "ANY" for r in result.routes)


def test_net_http_routes_skipped_when_gorilla_present(tmp_path: Path) -> None:
    """Gorilla wraps HandleFunc — only one set of routes should land per call."""
    (tmp_path / "main.go").write_text(
        'package main\n'
        '\n'
        'import (\n'
        '    "net/http"\n'
        '    "github.com/gorilla/mux"\n'
        ')\n'
        '\n'
        'func setup() {\n'
        '    r := mux.NewRouter()\n'
        '    r.HandleFunc("/x", handler).Methods("GET")\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    matches = [r for r in result.routes if r.path == "/x"]
    # Should only be one, not duplicated by both gorilla AND net/http extractors.
    assert len(matches) == 1
    assert matches[0].method == "GET"


# ---------- Databases ----------


def test_database_sql_postgres_emits_postgresql(tmp_path: Path) -> None:
    (tmp_path / "db.go").write_text(
        'package main\n\nimport "database/sql"\n\nfunc connect() {\n'
        '    db, _ := sql.Open("postgres", "host=...")\n'
        '    _ = db\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    assert any(d.kind == "postgresql" for d in result.databases)


def test_gorm_mysql_redis_each_emit_distinct_kinds(tmp_path: Path) -> None:
    (tmp_path / "gorm.go").write_text(
        'package db\nimport "gorm.io/driver/mysql"\nimport "gorm.io/gorm"\n'
        'func open() { gorm.Open(mysql.New(mysql.Config{}), &gorm.Config{}) }\n',
        encoding="utf-8",
    )
    (tmp_path / "mongo.go").write_text(
        'package db\nimport "go.mongodb.org/mongo-driver/mongo"\n'
        'func conn() { mongo.Connect(nil, nil) }\n',
        encoding="utf-8",
    )
    (tmp_path / "redis.go").write_text(
        'package db\nimport "github.com/redis/go-redis/v9"\n'
        'func client() { redis.NewClient(&redis.Options{}) }\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    kinds = {d.kind for d in result.databases}
    assert "mysql" in kinds
    assert "mongodb" in kinds
    assert "redis" in kinds


# ---------- Auth ----------


def test_jwt_bcrypt_oauth_emit_high_confidence_hints(tmp_path: Path) -> None:
    (tmp_path / "auth.go").write_text(
        'package auth\n'
        'import (\n'
        '    "github.com/golang-jwt/jwt/v5"\n'
        '    "golang.org/x/crypto/bcrypt"\n'
        '    "golang.org/x/oauth2"\n'
        ')\n'
        'func _x() { _ = jwt.MapClaims{}; _, _ = bcrypt.GenerateFromPassword(nil, 12); _ = oauth2.Config{} }\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    by_hint = {h.hint: h for h in result.auth_hints}
    assert "jwt" in by_hint
    assert "bcrypt" in by_hint
    assert "oauth" in by_hint
    assert by_hint["bcrypt"].confidence == 0.9
    assert by_hint["jwt"].confidence == 0.85


def test_authorization_keyword_yields_low_confidence(tmp_path: Path) -> None:
    (tmp_path / "headers.go").write_text(
        'package headers\nfunc x(h string) { if h == "Authorization" { _ = h } }\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    auth = next(h for h in result.auth_hints if h.hint == "authorization_header")
    assert auth.confidence == 0.6


# ---------- Secrets ----------


def test_os_getenv_secrets_extracted(tmp_path: Path) -> None:
    (tmp_path / "config.go").write_text(
        'package config\nimport "os"\n'
        'func load() {\n'
        '    _ = os.Getenv("JWT_SECRET")\n'
        '    _ = os.Getenv("DATABASE_PASSWORD")\n'
        '    _, _ = os.LookupEnv("STRIPE_API_KEY")\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    names = {s.name for s in result.secret_hints}
    assert "JWT_SECRET" in names
    assert "DATABASE_PASSWORD" in names
    assert "STRIPE_API_KEY" in names

    jwt = next(s for s in result.secret_hints if s.name == "JWT_SECRET")
    assert jwt.line == 4
    assert jwt.evidence_text and "JWT_SECRET" in jwt.evidence_text


def test_viper_secret_keys(tmp_path: Path) -> None:
    (tmp_path / "config.go").write_text(
        'package config\nimport "github.com/spf13/viper"\n'
        'func load() {\n'
        '    _ = viper.GetString("app.jwt_secret")\n'
        '    _ = viper.GetString("auth.access_token")\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    names = {s.name for s in result.secret_hints}
    assert any("jwt_secret" in n.lower() for n in names)
    assert any("access_token" in n.lower() for n in names)


# ---------- External calls ----------


def test_http_get_emits_external_call(tmp_path: Path) -> None:
    (tmp_path / "client.go").write_text(
        'package client\nimport "net/http"\n'
        'func fetch() { _, _ = http.Get("https://api.stripe.com/v1/charges") }\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    targets = {e.target for e in result.external_calls}
    assert "https://api.stripe.com/v1/charges" in targets


def test_relative_get_calls_skipped(tmp_path: Path) -> None:
    """Type method `.Get("foo")` on a non-HTTP type must not be picked up."""
    (tmp_path / "store.go").write_text(
        'package store\n'
        'type kv struct{ m map[string]string }\n'
        'func (s *kv) Get(k string) string { return s.m[k] }\n'
        'func use(s *kv) { _ = s.Get("api_key") }\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    assert result.external_calls == []


# ---------- Frameworks + entrypoints ----------


def test_framework_and_entrypoint_hints(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        'package main\n'
        'import (\n'
        '    "net/http"\n'
        '    "github.com/gin-gonic/gin"\n'
        ')\n'
        'func main() {\n'
        '    r := gin.Default()\n'
        '    r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "ok") })\n'
        '    r.Run(":8080")\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    fw = {f.hint for f in result.framework_hints}
    assert "gin" in fw
    assert "net-http" in fw

    ep = {e.hint for e in result.entrypoint_hints}
    assert "gin_run" in ep


def test_chi_listenandserve_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        'package main\n'
        'import (\n'
        '    "net/http"\n'
        '    "github.com/go-chi/chi/v5"\n'
        ')\n'
        'func main() {\n'
        '    r := chi.NewRouter()\n'
        '    r.Get("/", indexHandler)\n'
        '    http.ListenAndServe(":3000", r)\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    fw = {f.hint for f in result.framework_hints}
    assert "chi" in fw
    ep = {e.hint for e in result.entrypoint_hints}
    assert "net_http_listen" in ep


# ---------- go.mod → service hints ----------


def test_module_name_picked_up_as_service_hint(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module github.com/acme/billing-api\n\ngo 1.22\n",
        encoding="utf-8",
    )
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    result = GoAnalyzer().analyze(tmp_path)
    assert any(h.hint == "module:github.com/acme/billing-api" for h in result.service_hints)


# ---------- End-to-end sanity ----------


def test_full_gin_service_produces_expected_signal_set(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module github.com/acme/orders\n\ngo 1.22\n", encoding="utf-8"
    )
    (tmp_path / "main.go").write_text(
        'package main\n'
        '\n'
        'import (\n'
        '    "database/sql"\n'
        '    "net/http"\n'
        '    "os"\n'
        '\n'
        '    "github.com/gin-gonic/gin"\n'
        '    "github.com/golang-jwt/jwt/v5"\n'
        '    _ "github.com/lib/pq"\n'
        ')\n'
        '\n'
        'func main() {\n'
        '    _ = os.Getenv("JWT_SECRET")\n'
        '    _, _ = sql.Open("postgres", os.Getenv("DATABASE_URL"))\n'
        '    _ = jwt.MapClaims{}\n'
        '    _, _ = http.Get("https://api.example.com/data")\n'
        '\n'
        '    r := gin.Default()\n'
        '    r.POST("/login", loginHandler)\n'
        '    r.GET("/me", meHandler)\n'
        '    r.POST("/admin/users/:id/role", roleHandler)\n'
        '    r.Run(":8080")\n'
        '}\n'
        '\n'
        'func loginHandler(c *gin.Context) {}\n'
        'func meHandler(c *gin.Context)    {}\n'
        'func roleHandler(c *gin.Context)  {}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)

    pairs = {(r.path, r.method) for r in result.routes}
    assert pairs >= {("/login", "POST"), ("/me", "GET"), ("/admin/users/:id/role", "POST")}
    assert any(d.kind == "postgresql" for d in result.databases)
    assert any(h.hint == "jwt" for h in result.auth_hints)
    assert any(s.name == "JWT_SECRET" for s in result.secret_hints)
    assert any(e.target == "https://api.example.com/data" for e in result.external_calls)
    assert any(f.hint == "gin" for f in result.framework_hints)
    assert any(e.hint == "gin_run" for e in result.entrypoint_hints)
    assert any(h.hint == "module:github.com/acme/orders" for h in result.service_hints)

    assert all(r.line is not None for r in result.routes)
    jwt_secret = next(s for s in result.secret_hints if s.name == "JWT_SECRET")
    assert jwt_secret.line is not None
    assert jwt_secret.confidence == 0.85
