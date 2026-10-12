"""Tests for the GoAnalyzer plugin.

Each test writes a realistic Go snippet into tmp_path and asserts on the
resulting ScanResult. Line-number assertions verify the Signal v2 plumbing.
"""

from __future__ import annotations

import sys
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


# ---------- Repo walking (mlaify/AttackMap#253) ----------


def _write_gin_main(repo: Path) -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    main = repo / "main.go"
    main.write_text(
        'package main\n'
        '\n'
        'import "github.com/gin-gonic/gin"\n'
        '\n'
        'func main() {\n'
        '    r := gin.Default()\n'
        '    r.GET("/users", listUsers)\n'
        '    r.Run(":8080")\n'
        '}\n',
        encoding="utf-8",
    )
    return main


def test_repo_under_skip_dir_names_is_still_analyzed(tmp_path: Path) -> None:
    # "build" and "out" are skip dirs; they must only count inside the repo.
    repo = tmp_path / "build" / "out" / "repo"
    _write_gin_main(repo)
    analyzer = GoAnalyzer()
    assert analyzer.detect(repo) is True
    result = analyzer.analyze(repo)
    assert result.files_scanned == 1
    assert ("/users", "GET") in {(r.path, r.method) for r in result.routes}


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinked_file_outside_repo_is_not_analyzed(tmp_path: Path) -> None:
    target = _write_gin_main(tmp_path / "outside")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "linked.go").symlink_to(target)
    analyzer = GoAnalyzer()
    assert analyzer.detect(repo) is False
    result = analyzer.analyze(repo)
    assert result.files_scanned == 0
    assert result.routes == []


# ---------- False-positive routes and test code (#2) ----------


def test_chi_lookup_get_calls_produce_no_routes(tmp_path: Path) -> None:
    """Header/query/config `.Get("key")` lookups in a chi file are not routes."""
    (tmp_path / "main.go").write_text(
        'package main\n'
        '\n'
        'import (\n'
        '    "net/http"\n'
        '    "github.com/go-chi/chi/v5"\n'
        '    "github.com/spf13/viper"\n'
        ')\n'
        '\n'
        'func handler(w http.ResponseWriter, req *http.Request) {\n'
        '    token := req.Header.Get("Authorization")\n'
        '    q := req.URL.Query()\n'
        '    id := q.Get("id")\n'
        '    name := req.Form.Get("/name")\n'
        '    dsn := viper.Get("db.dsn")\n'
        '    _, _, _, _ = token, id, name, dsn\n'
        '}\n'
        '\n'
        'func main() {\n'
        '    r := chi.NewRouter()\n'
        '    r.Get("/users/{id}", handler)\n'
        '    http.ListenAndServe(":8080", r)\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    assert {(r.method, r.path) for r in result.routes} == {("GET", "/users/{id}")}


def test_fiber_ctx_get_produces_no_routes(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        'package main\n'
        '\n'
        'import "github.com/gofiber/fiber/v2"\n'
        '\n'
        'func main() {\n'
        '    app := fiber.New()\n'
        '    app.Get("/items", func(c *fiber.Ctx) error {\n'
        '        key := c.Get("X-Api-Key")\n'
        '        ref := c.Get("/referer", "none")\n'
        '        return c.SendString(key + ref)\n'
        '    })\n'
        '    app.Listen(":3000")\n'
        '}\n',
        encoding="utf-8",
    )
    result = GoAnalyzer().analyze(tmp_path)
    assert {(r.method, r.path) for r in result.routes} == {("GET", "/items")}


def _write_chi_with_tests(root: Path) -> None:
    (root / "main.go").write_text(
        'package main\n'
        '\n'
        'import "github.com/go-chi/chi/v5"\n'
        '\n'
        'func routes() {\n'
        '    r := chi.NewRouter()\n'
        '    r.Get("/users", listUsers)\n'
        '}\n',
        encoding="utf-8",
    )
    (root / "main_test.go").write_text(
        'package main\n'
        '\n'
        'import (\n'
        '    "net/http"\n'
        '    "net/http/httptest"\n'
        ')\n'
        '\n'
        'func TestX(t *testing.T) {\n'
        '    mux := http.NewServeMux()\n'
        '    mux.HandleFunc("/test-only", func(w http.ResponseWriter, r *http.Request) {})\n'
        '    srv := httptest.NewServer(mux)\n'
        '    defer srv.Close()\n'
        '}\n',
        encoding="utf-8",
    )
    fixture = root / "testdata"
    fixture.mkdir()
    (fixture / "server.go").write_text(
        'package fixture\n'
        '\n'
        'import "net/http"\n'
        '\n'
        'func init() { http.HandleFunc("/fixture-only", nil) }\n',
        encoding="utf-8",
    )


def test_test_files_and_testdata_not_scanned_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ATTACKMAP_INCLUDE_TESTS", raising=False)
    _write_chi_with_tests(tmp_path)
    result = GoAnalyzer().analyze(tmp_path)
    assert {(r.method, r.path, r.file) for r in result.routes} == {("GET", "/users", "main.go")}
    assert result.files_scanned == 1


def test_include_tests_env_opts_test_code_back_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATTACKMAP_INCLUDE_TESTS", "1")
    _write_chi_with_tests(tmp_path)
    result = GoAnalyzer().analyze(tmp_path)
    routes = {(r.path, r.file) for r in result.routes}
    assert ("/test-only", "main_test.go") in routes
    assert ("/fixture-only", "testdata/server.go") in routes
    assert result.files_scanned == 3


# ---------- Route.auth contract (AttackMap#256) ----------


def _routes(tmp_path: Path, name: str, source: str) -> dict:
    (tmp_path / name).write_text(source, encoding="utf-8")
    return {f"{r.method} {r.path}": r for r in GoAnalyzer().analyze(tmp_path).routes}


def test_gin_route_group_and_use_guards_are_required(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        "main.go",
        'package main\n\nimport "github.com/gin-gonic/gin"\n\n'
        "func main() {\n"
        "\tr := gin.Default()\n"
        '\tr.POST("/comments", AuthRequired(), createComment)\n'
        '\tadmin := r.Group("/admin", gin.BasicAuth(gin.Accounts{"foo": "bar"}))\n'
        '\tadmin.DELETE("/users/:id", deleteUser)\n'
        '\tapi := r.Group("/api")\n'
        '\tapi.POST("/early", early)\n'
        "\tapi.Use(AuthRequired())\n"
        '\tapi.PUT("/profile", updateProfile)\n'
        '\tr.POST("/login", login)\n'
        "}\n",
    )
    comments = routes["POST /comments"]
    assert comments.auth == "required"
    assert comments.guards == ["AuthRequired"]
    assert comments.guard_evidence == 'r.POST("/comments", AuthRequired(), createComment)'
    assert routes["DELETE /admin/users/:id"].guards == ["gin.BasicAuth"]
    assert routes["PUT /api/profile"].auth == "required"
    assert routes["PUT /api/profile"].guard_evidence == "api.Use(AuthRequired())"
    # gin copies a group's middleware at registration: an earlier route isn't guarded.
    assert routes["POST /api/early"].auth == "unknown"
    assert routes["POST /login"].auth == "unknown"
    assert routes["POST /login"].guard_evidence is None


def test_chi_use_group_and_with_guards(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        "routes.go",
        'package server\n\nimport (\n\t"github.com/go-chi/chi/v5"\n\t"github.com/go-chi/jwtauth/v5"\n)\n\n'
        "func Routes() *chi.Mux {\n"
        "\tr := chi.NewRouter()\n"
        '\tr.Post("/signup", signup)\n'
        '\tr.With(jwtauth.Verifier(ta), jwtauth.Authenticator(ta)).Post("/orders", createOrder)\n'
        "\tr.Group(func(r chi.Router) {\n"
        "\t\tr.Use(jwtauth.Verifier(ta))\n"
        "\t\tr.Use(jwtauth.Authenticator(ta))\n"
        '\t\tr.Delete("/orders/{id}", deleteOrder)\n'
        "\t})\n"
        '\tr.Route("/public", func(pr chi.Router) {\n'
        "\t\tpr.Use(jwtauth.Verifier(ta))\n"
        '\t\tpr.Post("/feedback", feedback)\n'
        "\t})\n"
        "\treturn r\n"
        "}\n",
    )
    # `r.With(...).Post(...)` is now a route, guarded inline.
    assert routes["POST /orders"].auth == "required"
    assert routes["POST /orders"].guards == ["jwtauth.Authenticator"]
    # The Group closure's Use applies inside it only.
    assert routes["DELETE /orders/{id}"].auth == "required"
    assert routes["POST /signup"].auth == "unknown"
    # jwtauth.Verifier only parses a token; it doesn't reject anonymous callers.
    assert routes["POST /public/feedback"].auth == "unknown"


def test_router_passed_as_parameter_keeps_its_use_guard(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        "routes.go",
        'package api\n\nimport "github.com/gin-gonic/gin"\n\n'
        "func Register(r *gin.RouterGroup) {\n"
        "\tr.Use(RequireUser())\n"
        '\tr.POST("/notes", createNote)\n'
        "}\n\n"
        "func RegisterPublic(r *gin.RouterGroup) {\n"
        '\tr.POST("/contact", contact)\n'
        "}\n",
    )
    assert routes["POST /notes"].auth == "required"
    # A different function's `r` is a different router.
    assert routes["POST /contact"].auth == "unknown"


def test_echo_skipper_paths_are_explicitly_public(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        "main.go",
        'package main\n\nimport (\n\techojwt "github.com/labstack/echo-jwt/v4"\n\t"github.com/labstack/echo/v4"\n)\n\n'
        "func main() {\n"
        "\te := echo.New()\n"
        "\te.Use(echojwt.WithConfig(echojwt.Config{\n"
        '\t\tSigningKey: []byte("k"),\n'
        "\t\tSkipper: func(c echo.Context) bool {\n"
        '\t\t\treturn c.Path() == "/register" || strings.HasPrefix(c.Path(), "/hooks/")\n'
        "\t\t},\n"
        "\t}))\n"
        '\te.POST("/register", register)\n'
        '\te.POST("/hooks/stripe", stripe)\n'
        '\te.PUT("/settings", settings)\n'
        "}\n",
    )
    register = routes["POST /register"]
    assert register.auth == "anonymous"
    assert register.guards == []
    assert register.guard_evidence.startswith("Skipper: func(c echo.Context) bool")
    assert routes["POST /hooks/stripe"].auth == "anonymous"
    assert routes["PUT /settings"].auth == "required"
    assert routes["PUT /settings"].guards == ["echojwt.WithConfig"]


def test_group_guard_skipper_opts_one_route_out(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        "main.go",
        'package main\n\nimport "github.com/labstack/echo/v4"\n\n'
        "func main() {\n"
        "\te := echo.New()\n"
        '\tapi := e.Group("/api", middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{\n'
        '\t\tSkipper: func(c echo.Context) bool { return c.Path() == "/api/status" },\n'
        "\t\tValidator: validateKey,\n"
        "\t}))\n"
        '\tapi.POST("/status", status)\n'
        '\tapi.POST("/jobs", createJob)\n'
        "}\n",
    )
    # The skipper sees the full path (group prefix + route path).
    assert routes["POST /api/status"].auth == "anonymous"
    assert routes["POST /api/jobs"].auth == "required"
    assert routes["POST /api/jobs"].guards == ["middleware.KeyAuthWithConfig"]


def test_fiber_use_order_and_unknowable_configs(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        "main.go",
        'package main\n\nimport "github.com/gofiber/fiber/v2"\n\n'
        "func main() {\n"
        "\tapp := fiber.New()\n"
        '\tapp.Post("/ping", ping)\n'
        '\tapp.Use(jwtware.New(jwtware.Config{SigningKey: jwtware.SigningKey{Key: []byte("s")}}))\n'
        '\tapp.Post("/items", createItem)\n'
        '\tv2 := fiber.New()\n'
        '\tv2.Use(keyauth.New(keyCfg))\n'
        '\tv2.Post("/things", createThing)\n'
        '\tv3 := fiber.New()\n'
        "\tv3.Use(jwtware.New(jwtware.Config{Filter: skipPublic}))\n"
        '\tv3.Post("/widgets", createWidget)\n'
        "}\n",
    )
    # fiber runs middleware in registration order: /ping comes before the Use.
    assert routes["POST /ping"].auth == "unknown"
    assert routes["POST /items"].auth == "required"
    # A config passed by variable, or a named skip function, could skip anything.
    assert routes["POST /things"].auth == "unknown"
    assert routes["POST /widgets"].auth == "unknown"


# ---------- Route shapes: ServeMux patterns, Handle, gorilla chains, prefixes (#3) ----------


def _scan(tmp_path: Path, name: str, source: str):
    (tmp_path / name).write_text(source, encoding="utf-8")
    return GoAnalyzer().analyze(tmp_path)


def test_servemux_method_and_host_patterns(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "main.go",
        'package main\n\nimport "net/http"\n\n'
        "func main() {\n"
        "\tmux := http.NewServeMux()\n"
        '\tmux.HandleFunc("GET /items/{id}", getItem)\n'
        '\tmux.HandleFunc("POST example.com/x", postX)\n'
        '\tmux.HandleFunc("DELETE\t/items/{id...}", deleteItem)\n'
        "\tmux.HandleFunc(`PUT /raw/{id}`, putRaw)\n"
        '\tmux.HandleFunc("/legacy", legacy)\n'
        '\tmux.HandleFunc("get /lower", lower)\n'
        '\tbus.Handle("event/created", onCreated)\n'
        '\thttp.ListenAndServe(":8080", mux)\n'
        "}\n",
    )
    pairs = {(r.method, r.path) for r in result.routes}
    assert pairs == {
        ("GET", "/items/{id}"),
        ("POST", "/x"),
        ("DELETE", "/items/{id...}"),
        ("PUT", "/raw/{id}"),
        ("ANY", "/legacy"),
    }
    # The host is kept as evidence of a host-scoped route.
    host = [h for h in result.service_hints if h.hint == "route_host:example.com"]
    assert len(host) == 1
    assert host[0].line == 8
    assert host[0].evidence_text == 'mux.HandleFunc("POST example.com/x", postX)'


def test_servemux_handle_routes_and_wrapped_auth(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        "main.go",
        'package main\n\nimport "net/http"\n\n'
        "func main() {\n"
        "\tmux := http.NewServeMux()\n"
        '\tmux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web"))))\n'
        '\tmux.Handle("POST /admin/reset", requireAuth(http.HandlerFunc(reset)))\n'
        '\tmux.Handle("POST /login", auth.LoginHandler(db))\n'
        '\tmux.Handle("POST /hook", authHandler)\n'
        '\thttp.Handle("/", mux)\n'
        '\thttp.ListenAndServe(":8080", nil)\n'
        "}\n",
    )
    assert set(routes) == {"ANY /static/", "POST /admin/reset", "POST /login", "POST /hook"}
    assert routes["POST /admin/reset"].auth == "required"
    assert routes["POST /admin/reset"].guards == ["requireAuth"]
    # A handler constructor in an auth package, or a bare handler named for
    # auth, isn't middleware.
    assert routes["POST /login"].auth == "unknown"
    assert routes["POST /hook"].auth == "unknown"


def test_gorilla_closure_wrapped_and_handle_routes(tmp_path: Path) -> None:
    """The issue's fixture: only `GET /a` came out before."""
    routes = _routes(
        tmp_path,
        "main.go",
        'package main\n\nimport (\n\t"net/http"\n\n\t"github.com/gorilla/mux"\n)\n\n'
        "func main() {\n"
        "\tr := mux.NewRouter()\n"
        '\tr.HandleFunc("/a", a).Methods("GET")\n'
        '\tr.HandleFunc("/b", func(w http.ResponseWriter, req *http.Request) {\n'
        '\t\tif req.Method == "POST" { w.WriteHeader(201) }\n'
        '\t}).Methods("POST")\n'
        '\tr.HandleFunc("/c", authMW(c)).Methods(http.MethodPut, http.MethodPatch)\n'
        '\tr.Handle("/d", d).Methods("DELETE")\n'
        '\tr.Path("/e").Methods("GET").HandlerFunc(e)\n'
        '\tr.PathPrefix("/static/").Handler(http.FileServer(http.Dir("web")))\n'
        "\tr.HandleFunc(`/raw`, raw)\n"
        '\tr.HandleFunc(path, dynamic)\n'
        '\thttp.Handle("/", r)\n'
        "}\n",
    )
    assert set(routes) == {
        "GET /a", "POST /b", "PUT /c", "PATCH /c", "DELETE /d", "GET /e", "ANY /static/", "ANY /raw",
    }
    assert routes["PUT /c"].auth == "required"
    assert routes["PUT /c"].guards == ["authMW"]
    assert routes["GET /a"].auth == "unknown"
    assert routes["POST /b"].line == 12


def test_gorilla_subrouter_prefix_and_use_guards(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        "main.go",
        'package main\n\nimport "github.com/gorilla/mux"\n\n'
        "func main() {\n"
        "\tr := mux.NewRouter()\n"
        '\tr.HandleFunc("/health", health)\n'
        '\tapi := r.PathPrefix("/api").Subrouter()\n'
        '\tapi.HandleFunc("/users", listUsers).Methods("GET")\n'
        "\tapi.Use(jwtMiddleware)\n"
        '\tv1 := api.PathPrefix("/v1").Methods("POST").Subrouter()\n'
        '\tv1.HandleFunc("/orders", createOrder).Methods("POST")\n'
        '\tpub := r.Host("{sub}.example.com").Subrouter()\n'
        '\tpub.HandleFunc("/feed", feed)\n'
        '\tdyn := r.PathPrefix(base).Subrouter()\n'
        '\tdyn.HandleFunc("/x", x)\n'
        "}\n",
    )
    assert set(routes) == {"ANY /health", "GET /api/users", "POST /api/v1/orders", "ANY /feed", "ANY /x"}
    # gorilla runs a router's middleware for all of its routes, whenever registered.
    assert routes["GET /api/users"].auth == "required"
    assert routes["GET /api/users"].guard_evidence == "api.Use(jwtMiddleware)"
    assert routes["POST /api/v1/orders"].auth == "required"
    assert routes["ANY /health"].auth == "unknown"
    assert routes["ANY /feed"].auth == "unknown"


def test_gin_nested_group_prefixes_and_group_use(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        "main.go",
        'package main\n\nimport "github.com/gin-gonic/gin"\n\n'
        "func main() {\n"
        "\tr := gin.Default()\n"
        '\tv1 := r.Group("/api/v1")\n'
        "\t{\n"
        '\t\tusers := v1.Group("/users")\n'
        '\t\tusers.GET("", listUsers)\n'
        '\t\tusers.GET("/:id", getUser)\n'
        '\t\tadmin := v1.Group("/admin/")\n'
        "\t\tadmin.Use(AuthRequired())\n"
        '\t\tadmin.POST("/reset", reset)\n'
        "\t}\n"
        "\tr.GET(`/raw`, raw)\n"
        '\tr.GET("", ignored)\n'
        "}\n",
    )
    assert set(routes) == {"GET /api/v1/users", "GET /api/v1/users/:id", "POST /api/v1/admin/reset", "GET /raw"}
    assert routes["POST /api/v1/admin/reset"].auth == "required"
    assert routes["GET /api/v1/users"].auth == "unknown"


def test_echo_group_prefix_carries_group_middleware(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        "main.go",
        'package main\n\nimport (\n\t"github.com/labstack/echo/v4"\n\t"github.com/labstack/echo/v4/middleware"\n)\n\n'
        "func main() {\n"
        "\te := echo.New()\n"
        '\tadmin := e.Group("/admin", middleware.JWT([]byte("secret")))\n'
        '\tadmin.POST("/reset", reset)\n'
        '\tusers := admin.Group("/users")\n'
        '\tusers.DELETE("/:id", deleteUser)\n'
        '\tpublic := e.Group("/public")\n'
        '\tpublic.POST("/contact", contact)\n'
        "}\n",
    )
    assert set(routes) == {"POST /admin/reset", "DELETE /admin/users/:id", "POST /public/contact"}
    assert routes["POST /admin/reset"].auth == "required"
    assert routes["DELETE /admin/users/:id"].guards == ["middleware.JWT"]
    assert routes["POST /public/contact"].auth == "unknown"


def test_fiber_group_and_route_prefixes(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        "main.go",
        'package main\n\nimport "github.com/gofiber/fiber/v2"\n\n'
        "func main() {\n"
        "\tapp := fiber.New()\n"
        '\tapi := app.Group("/api")\n'
        '\tv1 := api.Group("/v1", jwtware.New(jwtware.Config{SigningKey: jwtware.SigningKey{Key: key}}))\n'
        '\tv1.Get("/list", list)\n'
        '\tapi.Post("/ping", ping)\n'
        '\tapp.Route("/shop", func(router fiber.Router) {\n'
        '\t\trouter.Get("/items", items)\n'
        '\t})\n'
        "}\n",
    )
    assert set(routes) == {"GET /api/v1/list", "POST /api/ping", "GET /shop/items"}
    assert routes["GET /api/v1/list"].auth == "required"
    assert routes["POST /api/ping"].auth == "unknown"


_CHI_HEADER = 'package server\n\nimport (\n\t"net/http"\n\n\t"github.com/go-chi/chi/v5"\n)\n\n'


def test_chi_route_closure_prefix_and_auth(tmp_path: Path) -> None:
    """The issue's repro: `r.Route("/admin", ...) { r.Post("/reset") }` came out as `POST /reset`."""
    routes = _routes(
        tmp_path,
        "routes.go",
        _CHI_HEADER + "func Routes() http.Handler {\n"
        "\tr := chi.NewRouter()\n"
        '\tr.Route("/admin", func(r chi.Router) {\n'
        "\t\tr.Use(jwtauth.Authenticator(ta))\n"
        '\t\tr.Post("/reset", reset)\n'
        '\t\tr.Route("/users/{id}", func(r chi.Router) {\n'
        '\t\t\tr.Delete("/", deleteUser)\n'
        '\t\t\tr.Method("PUT", "/role", setRole)\n'
        '\t\t\tr.Handle("/metrics", metrics)\n'
        "\t\t})\n"
        "\t})\n"
        '\tr.Post("/signup", signup)\n'
        '\tr.Post(`/wrapped`, requireAuth(wrapped))\n'
        "\treturn r\n"
        "}\n",
    )
    assert set(routes) == {
        "POST /admin/reset", "DELETE /admin/users/{id}/", "PUT /admin/users/{id}/role",
        "ANY /admin/users/{id}/metrics", "POST /signup", "POST /wrapped",
    }
    for key in ("POST /admin/reset", "DELETE /admin/users/{id}/", "PUT /admin/users/{id}/role", "ANY /admin/users/{id}/metrics"):
        assert routes[key].auth == "required", key
        assert routes[key].guards == ["jwtauth.Authenticator"]
    assert routes["POST /signup"].auth == "unknown"
    assert routes["POST /wrapped"].auth == "required"


def test_chi_mount_prefixes(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        "routes.go",
        _CHI_HEADER + "func Routes(h *Handler) http.Handler {\n"
        "\tr := chi.NewRouter()\n"
        "\tr.Use(jwtauth.Authenticator(ta))\n"
        '\tr.Mount("/api", apiRouter())\n'
        '\tr.Mount("/things", h.Routes())\n'
        '\tr.Route("/users", userRoutes)\n'
        "\tsub := chi.NewRouter()\n"
        '\tsub.Get("/ping", ping)\n'
        '\tr.Mount("/sub", sub)\n'
        '\tr.Mount("/debug", middleware.Profiler())\n'
        "\treturn r\n"
        "}\n\n"
        "func apiRouter() http.Handler {\n"
        "\tr := chi.NewRouter()\n"
        '\tr.Get("/items", listItems)\n'
        "\treturn r\n"
        "}\n\n"
        "func (h *Handler) Routes() chi.Router {\n"
        "\tr := chi.NewRouter()\n"
        '\tr.Post("/", h.create)\n'
        "\treturn r\n"
        "}\n\n"
        "func userRoutes(r chi.Router) {\n"
        '\tr.Get("/{id}", getUser)\n'
        "}\n",
    )
    assert set(routes) == {"GET /api/items", "POST /things/", "GET /users/{id}", "GET /sub/ping"}
    # The parent's middleware runs before the mounted router's routes.
    for route in routes.values():
        assert route.auth == "required", route.path


def test_chi_mount_ambiguous_or_cyclic_keeps_route_path(tmp_path: Path) -> None:
    routes = _routes(
        tmp_path,
        "routes.go",
        _CHI_HEADER + "func Routes() http.Handler {\n"
        "\tr := chi.NewRouter()\n"
        '\tr.Get("/root", root)\n'
        "\tsub := chi.NewRouter()\n"
        '\tsub.Get("/ping", ping)\n'
        '\tr.Mount("/a", sub)\n'
        '\tr.Mount("/b", sub)\n'
        '\tr.Mount("/self", r)\n'
        "\tloop := chi.NewRouter()\n"
        '\tloop.Get("/x", x)\n'
        '\tsub.Mount("/loop", loop)\n'
        '\tloop.Mount("/back", sub)\n'
        "\treturn r\n"
        "}\n",
    )
    # Mounted at two prefixes: the route's own path, not a wrong one. A router
    # mounted into itself or its own subtree isn't re-parented.
    assert set(routes) == {"GET /root", "GET /ping", "GET /loop/x"}


def test_parameterless_group_closures_join_prefixes_only(tmp_path: Path) -> None:
    """gitea-style group-stack router: `m.Group("/x", func() {...}, mw...)`."""
    routes = _routes(
        tmp_path,
        "web.go",
        _CHI_HEADER + "func Routes(m *web.Router) {\n"
        '\tm.Group("/repos", func() {\n'
        '\t\tm.Get("/{id}", getRepo)\n'
        '\t\tm.Group("/{id}/settings", func() {\n'
        '\t\t\tm.Post("/delete", deleteRepo)\n'
        "\t\t}, reqRepoAdmin, webAuth.AllowBasic)\n"
        '\t\tm.Get("/{id}/stars", stars)\n'
        "\t}, checkTokenPublicOnly())\n"
        '\tm.Get("/explore", explore)\n'
        "}\n",
    )
    assert set(routes) == {"GET /repos/{id}", "POST /repos/{id}/settings/delete", "GET /repos/{id}/stars", "GET /explore"}
    # The wrapper's middleware semantics are unknown: no auth is declared.
    assert all(r.auth == "unknown" for r in routes.values())


def test_many_sibling_scopes_still_resolve(tmp_path: Path) -> None:
    """Hundreds of closed group scopes of the same router name are skipped, not walked."""
    groups = "".join(f'\tm.Group("/g{i}", func() {{\n\t\tm.Get("/x", h)\n\t}})\n' for i in range(400))
    routes = _routes(
        tmp_path,
        "web.go",
        _CHI_HEADER + "func Routes(m *web.Router) {\n" + groups + '\tm.Group("/late", func() {\n\t\tm.Post("/y", y)\n\t})\n}\n',
    )
    assert "POST /late/y" in routes
    assert "GET /g399/x" in routes
    assert len(routes) == 401


def _fuzz_sources() -> list[str]:
    """Route-heavy sources for the fuzz test: every shape this analyzer reads."""
    return [
        _CHI_HEADER + 'func R() {\n\tr := chi.NewRouter()\n\tr.Route("/a", func(r chi.Router) {\n'
        '\t\tr.Use(jwtauth.Authenticator(ta))\n\t\tr.Post(`/b`, requireAuth(h))\n\t\tr.Mount("/c", sub())\n\t})\n'
        '\tr.Route("/u", userRoutes)\n\tr.With(authMW).Get("/w", h)\n\tm.Group("/g", func() {\n\t\tm.Get("/x", h)\n\t}, mw)\n}\n'
        "func sub() http.Handler {\n\tr := chi.NewRouter()\n\tr.Get(\"/s\", h)\n\treturn r\n}\n"
        "func userRoutes(r chi.Router) {\n\tr.Get(\"/{id}\", h)\n}\n",
        'package main\n\nimport (\n\t"net/http"\n\t"github.com/gorilla/mux"\n)\n\nfunc main() {\n\tr := mux.NewRouter()\n'
        '\tapi := r.PathPrefix("/api").Subrouter()\n\tapi.Use(authMW)\n'
        '\tapi.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("}")) }).Methods("POST")\n'
        '\tr.Path("/e").Methods(http.MethodGet).HandlerFunc(requireAuth(e))\n\thttp.Handle("/", r)\n}\n',
        'package main\n\nimport "net/http"\n\nfunc main() {\n\tmux := http.NewServeMux()\n'
        '\tmux.HandleFunc("GET example.com/items/{id}", h) // "unterminated `raw\n'
        '\tmux.Handle("/x", requireAuth(h))\n\t/* { ( */\n}\n',
        'package main\n\nimport "github.com/gin-gonic/gin"\n\nfunc main() {\n\tr := gin.Default()\n'
        '\tv1 := r.Group("/v1", AuthRequired())\n\t{\n\t\tu := v1.Group("/u")\n\t\tu.Use(AuthRequired())\n'
        '\t\tu.GET("", h)\n\t}\n}\n',
    ]


def test_route_extraction_survives_garbage_and_truncation() -> None:
    """Truncated, bracket-shuffled and random input must never raise."""
    import random
    import time

    from attackmap_analyzer_go.contracts import ScanResult

    analyzer = GoAnalyzer()
    rng = random.Random(1234)
    vocab = [
        "{", "}", "(", ")", "[", "]", '"', "`", "'", ",", ".", "\n", " ", "//", "/*", "*/", "func()",
        "func(r chi.Router)", "r", "m", "sub", ":=", "=", "r.Route(", "r.Mount(", "m.Group(", ".Subrouter()",
        ".PathPrefix(", ".HandleFunc(", ".Handle(", ".Methods(", ".Use(", ".Get(", ".GET(", '"/x"', "`/y`",
        '"GET /z"', "chi.NewRouter()", "mux.NewRouter()", "gin.Default()", "authMW(h)", "requireAuth(", "go-chi/chi",
        "gorilla/mux", "net/http", "gin-gonic/gin", "fiber.New()", "echo.New()",
    ]
    start = time.monotonic()
    for source in _fuzz_sources():
        for cut in range(0, len(source), 7):
            analyzer._extract_routes(source[:cut], "f.go", ScanResult(root="."))
        for _ in range(60):
            chars = list(source)
            for _ in range(rng.randint(1, 8)):
                i = rng.randrange(len(chars))
                chars[i] = rng.choice("{}()[]\"`'\n")
            analyzer._extract_routes("".join(chars), "f.go", ScanResult(root="."))
    for _ in range(300):
        soup = "".join(rng.choice(vocab) for _ in range(rng.randint(1, 400)))
        analyzer._extract_routes(soup, "f.go", ScanResult(root="."))
    assert time.monotonic() - start < 60


def test_route_scopes_stay_linear_on_adversarial_nesting() -> None:
    import time

    from attackmap_analyzer_go.contracts import ScanResult

    depth = 2000
    nested = (
        _CHI_HEADER + "func R() {\n\tr := chi.NewRouter()\n"
        + '\tr.Route("/a", func(r chi.Router) {\n' * depth
        + '\tr.Get("/x", h)\n'
        + "\t})\n" * depth
        + "}\n"
    )
    unbalanced = _CHI_HEADER + 'func R() {\n' + '\tm.Group("/g", func() {\n\t\tm.Get("/x", h)\n' * 3000
    mounts = _CHI_HEADER + "func R() {\n\tr := chi.NewRouter()\n" + '\tr.Mount("/m", r)\n\tr.Route("/r", R)\n' * 3000 + "}\n"
    for source in (nested, unbalanced, mounts):
        result = ScanResult(root=".")
        start = time.monotonic()
        GoAnalyzer()._extract_routes(source, "f.go", result)
        assert time.monotonic() - start < 10
    # Derivation deeper than the walk limit keeps the path we could join.
    result = ScanResult(root=".")
    GoAnalyzer()._extract_routes(nested, "f.go", result)
    assert len(result.routes) == 1 and result.routes[0].path.endswith("/a/x")
