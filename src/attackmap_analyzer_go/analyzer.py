"""Go ecosystem analyzer for AttackMap.

Coverage (v0.1):
- Web frameworks: net/http (stdlib), chi, gin, echo, fiber, gorilla/mux
- Databases: database/sql, gorm, sqlx, pgx, mongo-go-driver, go-redis, bbolt
- Auth packages: golang-jwt/jwt, golang.org/x/oauth2, gorilla/sessions, casbin,
  golang.org/x/crypto/bcrypt and friends, x/crypto/scrypt, x/crypto/argon2
- HTTP clients (external calls): net/http (http.Get/Post), go-resty
- Secrets: os.Getenv, godotenv (joho/godotenv), viper.GetString
- Entrypoints: http.ListenAndServe, gin.Run, echo.Start, fiber.Listen
- Service hints: module name from go.mod

Emits Signal v2 fields (line numbers + evidence snippets + confidence) so
downstream insights can cite `path/to/file.go:NN`.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from attackmap.sdk import DEFAULT_SKIP_DIRS, iter_repo_files, line_of, read_source, rel

from . import route_auth as ra
from .contracts import (
    AnalyzerMetadata,
    AuthHint,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)

CODE_SUFFIXES = {".go"}
# vendor/, .git, node_modules, dist and build are all in the SDK defaults, which
# are matched against directory names inside the repo only (mlaify/AttackMap#253).
SKIP_DIRS = DEFAULT_SKIP_DIRS
# The go tool ignores `testdata/` directories: they hold fixtures, never code
# that ships. analyze() skips them along with `*_test.go` files unless test
# code is opted in with ATTACKMAP_INCLUDE_TESTS.
TEST_DATA_DIRS = frozenset({"testdata"})
INCLUDE_TESTS_ENV = "ATTACKMAP_INCLUDE_TESTS"
_SNIPPET_MAX_CHARS = 160


# ---------- Patterns ----------

# Gin: r.GET("/path", h), r.POST("/path", h), r.Group("/api")
# Method must be uppercase verb (Gin convention).
GIN_ROUTE_PATTERN = re.compile(
    r'\b(\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\(\s*"([^"]+)"',
)

# Chi: r.Get("/path", h), r.Post("/path", h)
# Title-case method (Chi convention). Same shape as Echo.
#
# Title-case `.Get(...)` is also the shape of every key/value lookup in Go
# (`req.Header.Get("Authorization")`, `q.Get("id")`, `viper.Get("key")`, fiber's
# `c.Get("X-Api-Key")`), so a registration must look like one: the path is a
# string literal starting with `/` (chi panics on anything else; fiber's
# catch-all `*` is the one exception) followed by a handler argument.
CHI_ECHO_ROUTE_PATTERN = re.compile(
    r'\b(\w+)\.(Get|Post|Put|Delete|Patch|Head|Options)\(\s*"([/*][^"]*)"\s*,',
)

# Chi inline middleware: r.With(mw...).Post("/path", h). The receiver's
# `.With(` is matched here; the chained verb call is read after its `)`.
CHI_WITH_PATTERN = re.compile(r"\b(\w+)\s*\.\s*With\s*\(")
CHI_WITH_CHAIN_PATTERN = re.compile(r"\s*\.\s*With\s*\(")
CHI_WITH_VERB_PATTERN = re.compile(
    r'\s*\.\s*(Get|Post|Put|Delete|Patch|Head|Options)\s*\(\s*"([/*][^"]*)"\s*,'
)

# Receivers that are never routers: request accessors (`r.Header.Get`,
# `r.URL.Query().Get`, `r.Form.Get`), config/env lookups, and the per-request
# context (`c`/`ctx`) whose `.Get` reads a header or a context value.
NON_ROUTER_RECEIVERS = frozenset(
    {
        "Header", "Query", "URL", "Form", "PostForm", "Trailer", "Values",
        "Cookies", "Params", "viper", "os", "c", "ctx",
    }
)

# Fiber: app.Get("/path", h)
# Same shape as chi/echo title-case but framework is detected by app.* + fiber import.

# Gorilla/mux: r.HandleFunc("/path", h).Methods("GET", "POST")
GORILLA_HANDLEFUNC_PATTERN = re.compile(
    r'\.HandleFunc\(\s*"([^"]+)"\s*,\s*\w+(?:\.\w+)*\s*\)(?P<chain>(?:\s*\.\s*\w+\([^)]*\))*)',
)
GORILLA_METHODS_PATTERN = re.compile(
    r'\.Methods\(\s*((?:"[A-Z]+"(?:\s*,\s*)?)+)\s*\)',
)

# net/http stdlib: http.HandleFunc("/path", h) or mux.HandleFunc("/path", h)
NET_HTTP_HANDLEFUNC_PATTERN = re.compile(
    r'\b(?:http|\w+)\.HandleFunc\(\s*"([^"]+)"\s*,',
)

# External HTTP calls
OUTBOUND_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'\bhttp\.(?:Get|Post|Head)\(\s*"(https?://[^"]+)"'),
    re.compile(r'\bhttp\.NewRequest\(\s*"[A-Z]+"\s*,\s*"(https?://[^"]+)"'),
    re.compile(r'\bresty\.New\(\)\.\w+\(\)\.\w+\(\s*"(https?://[^"]+)"'),
    re.compile(r'\bgrequests\.\w+\(\s*"(https?://[^"]+)"'),
    re.compile(r'\bclient\.\w+\(\s*ctx\s*,\s*"(https?://[^"]+)"', re.IGNORECASE),
]

# Database libs
DB_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\bsql\.Open\(\s*"postgres"'), "postgresql"),
    (re.compile(r'\bsql\.Open\(\s*"pgx"'), "postgresql"),
    (re.compile(r'\bsql\.Open\(\s*"mysql"'), "mysql"),
    (re.compile(r'\bsql\.Open\(\s*"sqlite3?"'), "sqlite"),
    (re.compile(r'\bsql\.Open\('), "sql"),
    (re.compile(r'\bgorm\.Open\(\s*postgres\.'), "postgresql"),
    (re.compile(r'\bgorm\.Open\(\s*mysql\.'), "mysql"),
    (re.compile(r'\bgorm\.Open\(\s*sqlite\.'), "sqlite"),
    (re.compile(r'\bgorm\.Open\('), "sql"),
    (re.compile(r'\bsqlx\.(?:Connect|Open|MustConnect)\('), "sql"),
    (re.compile(r'\bpgx\.(?:Connect|ConnectConfig)\(|\bpgxpool\.(?:New|Connect)\('), "postgresql"),
    (re.compile(r'\bmongo\.Connect\('), "mongodb"),
    (re.compile(r'\bredis\.NewClient\(|\bgo-redis\b'), "redis"),
    (re.compile(r'\bbolt\.Open\(|\bbbolt\.Open\('), "bolt"),
    (re.compile(r'\bs3\.New\w*\(|\baws-sdk-go(?:-v2)?/service/s3\b'), "object_storage"),
    (re.compile(r'\bdynamodb\.New\w*\('), "dynamodb"),
]

# Auth-related signals
AUTH_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(r'\bgolang-jwt/jwt\b|\bjwt-go\b|\bjwt\.(?:Parse|NewWithClaims|MapClaims)\b'), "jwt", 0.85),
    (re.compile(r'\bx/crypto/bcrypt\b|\bbcrypt\.GenerateFromPassword\b'), "bcrypt", 0.9),
    (re.compile(r'\bx/crypto/argon2\b|\bargon2\.IDKey\b'), "argon2", 0.9),
    (re.compile(r'\bx/crypto/scrypt\b'), "scrypt", 0.9),
    (re.compile(r'\bx/oauth2\b|\boauth2\.Config\b'), "oauth", 0.85),
    (re.compile(r'\bgorilla/sessions\b|\bsessions\.NewCookieStore\('), "gorilla_sessions", 0.85),
    (re.compile(r'\bcasbin\.NewEnforcer\(|\bcasbin/v\d+\b'), "casbin_authz", 0.9),
    (re.compile(r'\bgo-chi/jwtauth\b|\bjwtauth\.New\('), "chi_jwtauth", 0.85),
    (re.compile(r'\bechojwt\b|\becho-jwt\b'), "echo_jwt", 0.85),
    (re.compile(r'\bAuthorization\b'), "authorization_header", 0.6),
    (re.compile(r'\bBearer\b'), "bearer_token", 0.6),
    (re.compile(r'\bapi[_-]?key\b', re.IGNORECASE), "api_key", 0.6),
]

# Web framework presence
FRAMEWORK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\bgithub\.com/gin-gonic/gin\b|\bgin\.(?:Default|New|Engine)\('), "gin"),
    (re.compile(r'\bgithub\.com/go-chi/chi\b|\bchi\.(?:NewRouter|NewMux)\('), "chi"),
    (re.compile(r'\bgithub\.com/labstack/echo\b|\becho\.New\('), "echo"),
    (re.compile(r'\bgithub\.com/gofiber/fiber\b|\bfiber\.New\('), "fiber"),
    (re.compile(r'\bgithub\.com/gorilla/mux\b|\bmux\.NewRouter\('), "gorilla-mux"),
    (re.compile(r'\bgithub\.com/gorilla/sessions\b'), "gorilla-sessions"),
    (re.compile(r'\bnet/http\b|\bhttp\.HandleFunc\b'), "net-http"),
    (re.compile(r'\bgrpc\.NewServer\(|\bgoogle\.golang\.org/grpc\b'), "grpc"),
]

# Entrypoint markers
ENTRYPOINT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\bhttp\.ListenAndServe(?:TLS)?\('), "net_http_listen"),
    (re.compile(r'\b\w+\.ListenAndServe\(\)'), "server_listen"),
    (re.compile(r'\b\w+\.Run\(\s*"[^"]*"\s*\)'), "gin_run"),
    (re.compile(r'\b\w+\.Start\(\s*"[^"]*"\s*\)'), "echo_start"),
    (re.compile(r'\b\w+\.Listen\(\s*"[^"]*"\s*\)'), "fiber_listen"),
    (re.compile(r'\bgrpc\.NewServer\('), "grpc_server"),
]

# Secrets — Go env access patterns
SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r'\bos\.Getenv\(\s*"([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|PASS|PWD)[A-Z0-9_]*)"',
    ),
    re.compile(
        r'\bos\.LookupEnv\(\s*"([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|PASS|PWD)[A-Z0-9_]*)"',
    ),
    re.compile(
        r'\bgodotenv\.\w+\(.*?"([A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD|PASS|PWD)[A-Z0-9_]*)"',
        re.DOTALL,
    ),
    re.compile(
        r'\bviper\.(?:GetString|Get)\(\s*"([A-Za-z0-9_.]*(?:secret|token|key|password|pass|pwd)[A-Za-z0-9_.]*)"',
        re.IGNORECASE,
    ),
]


# Kept rather than attackmap.sdk.line_snippet: this takes a match offset and
# splits on "\n" only, so it stays consistent with line_of() on files that
# contain form feeds or other str.splitlines() separators, and it costs
# O(line) per match instead of O(file).
def _line_snippet(content: str, offset: int, *, max_chars: int = _SNIPPET_MAX_CHARS) -> str:
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > max_chars:
        line = line[: max_chars - 1] + "…"
    return line


def _module_name_from_gomod(gomod_path: Path, root: Path | None = None) -> str | None:
    text = read_source(gomod_path, root=root)
    if text is None:
        return None
    match = re.search(r"^\s*module\s+([^\s]+)\s*$", text, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return None


# Frameworks whose route extractor uses chi/echo title-case shape; we only call
# the relevant extractor when the file looks like it's using that framework, to
# avoid double-counting (chi.Get, echo.Get, fiber.Get all match the same regex).
def _file_is_chi(content: str) -> bool:
    return "go-chi/chi" in content or "chi.NewRouter" in content or "chi.NewMux" in content


def _file_is_echo(content: str) -> bool:
    return "labstack/echo" in content or "echo.New(" in content


def _file_is_fiber(content: str) -> bool:
    return "gofiber/fiber" in content or "fiber.New(" in content


def _file_is_gin(content: str) -> bool:
    return "gin-gonic/gin" in content or "gin.Default(" in content or "gin.New(" in content or "gin.Engine" in content


def _file_is_gorilla_mux(content: str) -> bool:
    return "gorilla/mux" in content or "mux.NewRouter(" in content


def _file_is_net_http(content: str) -> bool:
    return "net/http" in content or "http.HandleFunc" in content


class GoAnalyzer:
    metadata = AnalyzerMetadata(
        name="go",
        display_name="Go Analyzer",
        version="0.1.0",
        description="Go ecosystem analyzer covering net/http, chi, gin, echo, fiber, gorilla/mux, and common DB/auth packages.",
        scope="Go modules and workspaces. go.mod-bearing repos are auto-detected; pure .go trees also work.",
        targets=["go", "golang", "gin", "chi", "echo", "fiber"],
        languages=["go"],
        priority=20,
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    # ---------- Public entry points ----------

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False
        if (root / "go.mod").exists() or (root / "go.sum").exists():
            return True
        # Any nested go.mod or .go file; stop at the first one.
        return next(iter_repo_files(root, suffixes=CODE_SUFFIXES, names={"go.mod"}, skip_dirs=SKIP_DIRS), None) is not None

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        module_name = _module_name_from_gomod(root / "go.mod", root)
        if module_name:
            self._append_unique_service(result, f"module:{module_name}", "go.mod")

        # `*_test.go` and `testdata/` are test code: httptest registrations in
        # them are not production routes (#2). ATTACKMAP_INCLUDE_TESTS opts in.
        include_tests = bool(os.environ.get(INCLUDE_TESTS_ENV))
        skip_dirs = SKIP_DIRS if include_tests else SKIP_DIRS | TEST_DATA_DIRS
        for file_path in iter_repo_files(
            root, suffixes=CODE_SUFFIXES, skip_dirs=skip_dirs, include_tests=include_tests
        ):
            content = read_source(file_path, root=root)
            if content is None:
                continue

            result.files_scanned += 1
            if "go" not in result.languages:
                result.languages.append("go")

            relative = rel(file_path, root)
            self._extract_routes(content, relative, result)
            self._extract_databases(content, relative, result)
            self._extract_auth(content, relative, result)
            self._extract_secrets(content, relative, result)
            self._extract_external_calls(content, relative, result)
            self._extract_frameworks(content, relative, result)
            self._extract_entrypoints(content, relative, result)
            self._infer_service_role(content, relative, result)

        result.languages.sort()
        return result

    # ---------- Extractors ----------

    def _extract_routes(self, content: str, relative: str, result: ScanResult) -> None:
        is_gin = _file_is_gin(content)
        is_chi = _file_is_chi(content)
        is_echo = _file_is_echo(content)
        is_fiber = _file_is_fiber(content)
        is_gorilla = _file_is_gorilla_mux(content)
        is_net_http = _file_is_net_http(content)
        routers: list[ra.FileRouters] = []  # built on first use

        def resolve(receiver: str, offset: int, path: str, local: list[ra.Guard]) -> ra.Resolution:
            if not routers:
                routers.append(ra.FileRouters(content))
            return routers[0].resolve_route(receiver, offset, path, local)

        def local_guards(start: int, paren: int, first: int, last: int | None) -> list[ra.Guard] | None:
            """Auth middleware among a registration's arguments [first:last];
            the evidence quotes the registration from ``start``."""
            close = ra.matching_close(content, paren)
            if close < 0:
                return None
            context = content[start : min(close + 1, start + 400)]
            args = ra.split_args(content, paren, close)[first:last]
            return [g for s, e in args if (g := ra.guard_from_arg(content, s, e, context))]

        # Gin / echo: uppercase verb method (r.GET, e.POST, ...). Echo's runtime API
        # is the same uppercase shape as gin's despite different surface labels.
        # Route middleware: gin `r.POST(path, mw..., h)`, echo `e.POST(path, h, mw...)`.
        if is_gin or is_echo:
            echo_args = is_echo and not is_gin
            for match in GIN_ROUTE_PATTERN.finditer(content):
                method, path = match.group(2).upper(), match.group(3)
                index = self._append_unique_route(result, path, method, relative, line_of(content, match.start()))
                if index is None:
                    continue
                paren = content.find("(", match.start())
                local = local_guards(match.start(), paren, 2, None) if echo_args else local_guards(match.start(), paren, 1, -1)
                if local is not None:
                    self._set_route_auth(result, index, resolve(match.group(1), match.start(), path, local))

        # Chi / fiber: title-case verb method (r.Get, app.Post, ...). Only run when
        # we know which framework is in this file; otherwise we'd mis-attribute
        # generic `.Get(...)` calls on non-router types.
        # Route middleware: fiber `app.Post(path, mw..., h)`; chi uses `.With(mw)`.
        if is_chi or is_fiber:
            for match in CHI_ECHO_ROUTE_PATTERN.finditer(content):
                if match.group(1) in NON_ROUTER_RECEIVERS:
                    continue
                method, path = match.group(2).upper(), match.group(3)
                index = self._append_unique_route(result, path, method, relative, line_of(content, match.start()))
                if index is None:
                    continue
                paren = content.find("(", match.start())
                local = local_guards(match.start(), paren, 1, -1) if is_fiber and not is_chi else []
                if local is not None:
                    self._set_route_auth(result, index, resolve(match.group(1), match.start(), path, local))

        # Chi inline middleware: r.With(mw...)[.With(mw...)].Post("/path", h).
        if is_chi:
            for match in CHI_WITH_PATTERN.finditer(content):
                if match.group(1) in NON_ROUTER_RECEIVERS:
                    continue
                local: list[ra.Guard] = []
                paren = match.end() - 1
                while True:
                    guards = local_guards(match.start(), paren, 0, None)
                    close = ra.matching_close(content, paren)
                    if guards is None:
                        break
                    local += guards
                    chained = CHI_WITH_CHAIN_PATTERN.match(content, close + 1)
                    if chained:
                        paren = chained.end() - 1
                        continue
                    verb = CHI_WITH_VERB_PATTERN.match(content, close + 1)
                    if verb:
                        method, path = verb.group(1).upper(), verb.group(2)
                        line = line_of(content, match.start())
                        index = self._append_unique_route(result, path, method, relative, line)
                        if index is not None:
                            self._set_route_auth(result, index, resolve(match.group(1), match.start(), path, local))
                    break

        # Gorilla/mux: HandleFunc + chained .Methods("GET", "POST")
        if is_gorilla:
            for match in GORILLA_HANDLEFUNC_PATTERN.finditer(content):
                path = match.group(1)
                line = line_of(content, match.start())
                chain = match.group("chain") or ""
                methods_match = GORILLA_METHODS_PATTERN.search(chain)
                if methods_match:
                    methods = re.findall(r'"([A-Z]+)"', methods_match.group(1))
                    if methods:
                        for method in methods:
                            self._append_unique_route(result, path, method, relative, line)
                        continue
                self._append_unique_route(result, path, "ANY", relative, line)

        # net/http stdlib: http.HandleFunc / mux.HandleFunc — always emit, but only
        # when the file isn't already covered by gorilla/mux (which uses HandleFunc too
        # but wraps it with .Methods()).
        if is_net_http and not is_gorilla:
            for match in NET_HTTP_HANDLEFUNC_PATTERN.finditer(content):
                path = match.group(1)
                self._append_unique_route(result, path, "ANY", relative, line_of(content, match.start()))

    def _extract_databases(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DB_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_database(
                result, kind, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_auth(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint, confidence in AUTH_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_auth(
                result, hint, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
                confidence,
            )

    def _extract_secrets(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                groups = match.groups()
                name = groups[0] if groups and groups[0] else "unknown"
                self._append_unique_secret(
                    result, name, relative,
                    line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_external_calls(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in OUTBOUND_PATTERNS:
            for match in pattern.finditer(content):
                target = match.group(1)
                if not (target.startswith("http://") or target.startswith("https://")):
                    continue
                self._append_unique_external(
                    result, target, relative,
                    line_of(content, match.start()),
                    _line_snippet(content, match.start()),
                )

    def _extract_frameworks(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, name in FRAMEWORK_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_framework(
                result, name, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_entrypoints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in ENTRYPOINT_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            self._append_unique_entrypoint(
                result, hint, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _infer_service_role(self, content: str, relative: str, result: ScanResult) -> None:
        haystack = (relative + " " + content[:500]).lower()
        role: str | None = None
        if any(token in haystack for token in ("worker", "consumer", "queue", "background", "cronjob")):
            role = "worker"
        elif any(token in haystack for token in ("api", "server", "handler", "router", "controller")):
            role = "api"
        elif any(token in haystack for token in ("client", "sdk")):
            role = "client"
        if role:
            self._append_unique_service(result, f"service_role:{role}", relative)

    # ---------- Append helpers (dedup-aware) ----------

    @staticmethod
    def _append_unique_route(
        result: ScanResult,
        path: str,
        method: str,
        file: str,
        line: int | None,
        *,
        auth: str = ra.UNKNOWN,
        guards: list[str] | None = None,
        guard_evidence: str | None = None,
    ) -> int | None:
        """Append a route once per (path, method, file); return its index, or
        None when it was already recorded."""
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return None
        result.routes.append(
            Route(
                path=path, method=method, file=file, line=line,
                auth=auth, guards=list(guards or []), guard_evidence=guard_evidence,
            )
        )
        return len(result.routes) - 1

    @staticmethod
    def _set_route_auth(result: ScanResult, index: int, resolution: ra.Resolution) -> None:
        """Declare a route's auth (AttackMap#256); older cores ignore the fields.
        Rebuilt rather than mutated so Route's guard_evidence redaction runs."""
        if resolution.auth == ra.UNKNOWN:
            return
        route = result.routes[index]
        result.routes[index] = Route(
            path=route.path, method=route.method, file=route.file, line=route.line,
            auth=resolution.auth, guards=list(resolution.guards), guard_evidence=resolution.evidence,
        )

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        result.databases.append(DatabaseHint(kind=kind, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_auth(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None, confidence: float) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.auth_hints):
            return
        result.auth_hints.append(AuthHint(hint=hint, file=file, line=line, evidence_text=evidence, confidence=confidence))

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        result.secret_hints.append(SecretHint(name=name, file=file, line=line, evidence_text=evidence, confidence=0.85))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        result.external_calls.append(ExternalCall(target=target, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_framework(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.framework_hints):
            return
        result.framework_hints.append(FrameworkHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_entrypoint(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.entrypoint_hints):
            return
        result.entrypoint_hints.append(EntrypointHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_service(result: ScanResult, hint: str, file: str) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.service_hints):
            return
        result.service_hints.append(ServiceHint(hint=hint, file=file))


__all__ = ["GoAnalyzer"]
