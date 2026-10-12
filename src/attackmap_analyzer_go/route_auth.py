"""Route-level auth resolution for the AttackMap#256 contract.

Each emitted ``Route`` carries ``auth`` (``required`` / ``anonymous`` /
``unknown``), the ``guards`` that apply and the ``guard_evidence`` source text
that established the state. Core trusts a declared state over its own
resolution (which can't read Go), so this only declares what the source
verifiably says.

Routers are tracked by variable within a file:

- roots: ``r := chi.NewRouter()``, ``gin.Default()``, ``echo.New()``,
  ``fiber.New()``; any other receiver is bound to its enclosing top-level
  function (a router passed in as a parameter);
- derived routers: ``g := r.Group("/api", mw...)`` (gin / echo / fiber),
  ``g := r.With(mw...)`` (chi), gorilla ``g := r.PathPrefix("/api").Subrouter()``,
  and closure routers ``r.Group(func(r chi.Router) {...})`` /
  ``r.Route("/x", func(r chi.Router) {...})`` (and gitea-style parameterless
  ``m.Group("/x", func() {...})``), which inherit the parent's middleware;
- mounted routers: ``r.Mount("/x", sub)``, ``r.Mount("/x", build())`` and
  ``r.Route("/x", register)`` hang a router built in this file (or a
  function's router parameter) under ``r``;
- each derivation carries its path prefix, so a route's path is joined with
  every literal prefix above it (``Resolution.path``);
- ``X.Use(mw...)`` applies to routes registered on ``X`` (or routers derived
  from it) after the call, which is how gin, echo groups and fiber behave and
  the only order chi allows (gorilla applies it to every route of ``X``);
  fiber ``X.Use("/prefix", mw)`` only to paths under the prefix;
- route-local middleware: gin / fiber ``r.POST("/x", mw..., h)``, echo
  ``e.POST("/x", h, mw...)``, chi ``r.With(mw...).Post("/x", h)``, and a
  handler wrapped in middleware (``mux.Handle("/x", requireAuth(h))``).

A middleware counts as a guard when its name says it authenticates
(``AuthRequired()``, ``jwtauth.Authenticator``, ``middleware.JWT(...)``,
``echojwt.WithConfig(...)``, ``jwtware.New(...)``, ``keyauth.New(...)``,
``BasicAuth``). ``jwtauth.Verifier`` only parses a token, and ``Optional*``
middleware admits anonymous callers, so neither counts.

A guard's ``Skipper`` / ``Next`` / ``Filter`` function that only compares the
request path with literals (``c.Path() == "/signup"``,
``strings.HasPrefix(c.Path(), "/public")``) is an explicit opt-out: the
routes it names are ``anonymous`` when no other guard applies. Any other
skipper, or a config passed by variable, makes the guard uncertain, and the
route stays ``unknown``.

Linear: brackets are matched in one cached pass per file, argument lists are
split by jumping over nested brackets, a lookup climbs enclosing blocks (not
sibling ones), and lookups, chains and derivation depth are bounded.
"""

from __future__ import annotations

import bisect
import functools
import re
from dataclasses import dataclass, field

REQUIRED = "required"
ANONYMOUS = "anonymous"
UNKNOWN = "unknown"

_EVIDENCE_MAX = 200
# Enclosing blocks climbed to find a router variable's binding before giving up
# (the route stays unknown).
_LOOKUP_LIMIT = 64
# Router derivation depth followed before giving up.
_MAX_DEPTH = 32
_ARG_SCAN = 4000


def clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _EVIDENCE_MAX else text[: _EVIDENCE_MAX - 1] + "…"


# ---------- Brackets ----------

_SCAN_TOKEN = re.compile(r"[\"'`]|//|/\*|[()\[\]{}]")
_STRING_BODY = {
    '"': re.compile(r'[^"\\\n]*(?:\\.[^"\\\n]*)*"'),
    "'": re.compile(r"[^'\\\n]*(?:\\.[^'\\\n]*)*'"),
    "`": re.compile(r"[^`]*`"),
}
_OPEN = "([{"


@functools.lru_cache(maxsize=4)
def bracket_pairs(content: str) -> dict[int, int]:
    """Opening-bracket offset -> closing-bracket offset, in one forward pass
    (Go strings, raw strings, runes and comments skipped)."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    pos = 0
    n = len(content)
    while pos < n:
        match = _SCAN_TOKEN.search(content, pos)
        if not match:
            break
        token = match.group()
        pos = match.end()
        if token in _STRING_BODY:
            body = _STRING_BODY[token].match(content, pos)
            pos = body.end() if body else pos
        elif token == "//":
            nl = content.find("\n", pos)
            pos = n if nl < 0 else nl
        elif token == "/*":
            end = content.find("*/", pos)
            pos = n if end < 0 else end + 2
        elif token in _OPEN:
            stack.append(match.start())
        elif stack:
            pairs[stack.pop()] = match.start()
    return pairs


@functools.lru_cache(maxsize=4)
def literal_spans(content: str) -> tuple[list[int], list[int]]:
    """Starts and ends of Go strings, raw strings, runes and comments, in one
    forward pass (the same tokens `bracket_pairs` skips)."""
    starts: list[int] = []
    ends: list[int] = []
    pos = 0
    n = len(content)
    while pos < n:
        match = _SCAN_TOKEN.search(content, pos)
        if not match:
            break
        token = match.group()
        pos = match.end()
        if token in _STRING_BODY:
            body = _STRING_BODY[token].match(content, pos)
            pos = body.end() if body else pos
        elif token == "//":
            nl = content.find("\n", pos)
            pos = n if nl < 0 else nl
        elif token == "/*":
            end = content.find("*/", pos)
            pos = n if end < 0 else end + 2
        else:
            continue
        starts.append(match.start())
        ends.append(pos)
    return starts, ends


def in_literal(content: str, offset: int) -> bool:
    starts, ends = literal_spans(content)
    index = bisect.bisect_right(starts, offset) - 1
    return index >= 0 and offset < ends[index]


def matching_close(content: str, open_idx: int) -> int:
    if open_idx < 0:
        return -1
    return bracket_pairs(content).get(open_idx, -1)


_ARG_TOKEN = re.compile(r"[\"'`,]|//|/\*|[(\[{]")


def split_args(content: str, open_idx: int, close: int) -> list[tuple[int, int]]:
    """``(start, end)`` offsets of each top-level argument of the call whose
    ``(`` is at ``open_idx``.

    Nested brackets and strings are jumped over, so the cost is the number of
    top-level tokens, not the size of nested closures.
    """
    pairs = bracket_pairs(content)
    args: list[tuple[int, int]] = []
    start = pos = open_idx + 1
    while pos < close:
        match = _ARG_TOKEN.search(content, pos, close)
        if not match:
            break
        token = match.group()
        pos = match.end()
        if token == ",":
            args.append((start, match.start()))
            start = pos
        elif token in _STRING_BODY:
            body = _STRING_BODY[token].match(content, pos, close)
            pos = body.end() if body else pos
        elif token == "//":
            nl = content.find("\n", pos, close)
            pos = close if nl < 0 else nl
        elif token == "/*":
            end = content.find("*/", pos, close)
            pos = close if end < 0 else end + 2
        else:  # an opening bracket: jump to its partner
            pos = max(pos, pairs.get(match.start(), close - 1) + 1)
    if content[start:close].strip():
        args.append((start, close))
    return args


_STRING_LITERAL = re.compile(r'\s*(?:"([^"\\]*)"|`([^`]*)`)\s*$')


def string_literal(text: str) -> str | None:
    """The value of an interpreted (``"..."``, no escapes) or raw (`` `...` ``)
    Go string literal, or None when ``text`` is anything else."""
    match = _STRING_LITERAL.match(text)
    if not match:
        return None
    return match.group(1) if match.group(1) is not None else match.group(2)


def join_paths(prefix: str, path: str) -> str:
    """Join a group prefix and a route path the way gin / echo / fiber / chi
    do: one ``/`` between them, and the route's trailing slash kept."""
    if not prefix:
        return path
    if not path:
        return prefix
    return prefix.rstrip("/") + "/" + path.lstrip("/")


_CHAIN_SEGMENT = re.compile(r"\s*\.\s*(\w+)\s*\(")
_MAX_CHAIN = 16


def walk_chain(content: str, pos: int) -> list[tuple[str, int, int]]:
    """``(name, open, close)`` of each ``.Name(...)`` call chained from
    ``pos`` (gorilla's ``r.Path("/x").Methods("GET").HandlerFunc(h)``),
    at most ``_MAX_CHAIN`` of them; stops at an unbalanced call."""
    segments: list[tuple[str, int, int]] = []
    for _ in range(_MAX_CHAIN):
        match = _CHAIN_SEGMENT.match(content, pos)
        if not match:
            break
        close = matching_close(content, match.end() - 1)
        if close < 0:
            break
        segments.append((match.group(1), match.end() - 1, close))
        pos = close + 1
    return segments


# ---------- Guards ----------

# The middleware expression's name: `AuthRequired`, `jwtauth.Authenticator`,
# `middleware.JWTWithConfig`, `authMiddleware.MiddlewareFunc`.
_ARG_NAME = re.compile(r"\s*&?([A-Za-z_][\w.]*)")
_AUTH_NAME = re.compile(
    r"auth(?!or)|jwt|bearer|api_?key|login_?required|require_?(?:user|login)"
    r"|(?:require|verify|check|validate)_?token",
    re.IGNORECASE,
)
# jwtauth.Verifier only parses a token (Authenticator rejects); Optional*
# middleware admits anonymous callers.
_NOT_A_GUARD = re.compile(r"optional|\bverifier\b|\.Verifier$|maybe", re.IGNORECASE)
_CONFIG_CTOR = re.compile(r"(?:WithConfig|New|Config)$")
_SKIPPER_KEY = re.compile(r"\b(Skipper|Next|Filter)\s*:\s*")
_FUNC_LIT = re.compile(r"func\s*\(")
_PATH_EXPR = (
    r"\w+\s*\.\s*(?:Path\s*\(\s*\)|Request\s*\(\s*\)\s*\.\s*URL\s*\.\s*Path"
    r"|OriginalURL\s*\(\s*\)|Route\s*\(\s*\)\s*\.\s*Path)"
)
_SKIP_EXACT = re.compile(_PATH_EXPR + r'\s*==\s*"([^"\\]*)"|"([^"\\]*)"\s*==\s*' + _PATH_EXPR)
_SKIP_PREFIX = re.compile(r'strings\s*\.\s*HasPrefix\s*\(\s*' + _PATH_EXPR + r'\s*,\s*"([^"\\]*)"\s*\)')
_SKIP_GLUE = re.compile(r"\breturn\b|\|\||[(){}]")
_SKIPPER_BODY_MAX = 2000


@dataclass
class Skipper:
    """A guard's skip function: which paths it lets through unauthenticated."""

    exact: set[str]
    prefixes: set[str]
    characterized: bool  # body is only literal path comparisons
    evidence: str

    def skips(self, path: str) -> bool:
        return path in self.exact or any(path.startswith(p) for p in self.prefixes)


@dataclass
class Guard:
    name: str
    evidence: str
    skipper: Skipper | None = None
    uncertain: bool = False  # e.g. a config passed by variable: may skip anything
    prefix: str | None = None  # fiber `Use("/prefix", mw)`: only under this path


def _skipper(content: str, start: int, end: int) -> Skipper | None:
    key = _SKIPPER_KEY.search(content, start, end)
    if not key:
        return None
    evidence = clip(content[key.start() : min(end, key.start() + _EVIDENCE_MAX)])
    func = _FUNC_LIT.match(content, key.end())
    if not func:
        return Skipper(set(), set(), False, evidence)  # a named function: body not here
    body_open = content.find("{", matching_close(content, func.end() - 1) + 1, end)
    body_close = matching_close(content, body_open)
    if body_open < 0 or body_close < 0 or body_close - body_open > _SKIPPER_BODY_MAX:
        return Skipper(set(), set(), False, evidence)
    body = content[body_open + 1 : body_close]
    exact = {m.group(1) if m.group(1) is not None else m.group(2) for m in _SKIP_EXACT.finditer(body)}
    prefixes = {m.group(1) for m in _SKIP_PREFIX.finditer(body)}
    residue = _SKIP_GLUE.sub(" ", _SKIP_PREFIX.sub(" ", _SKIP_EXACT.sub(" ", body)))
    evidence = clip(content[key.start() : body_close + 1])
    return Skipper(exact, prefixes, not residue.strip() and bool(exact or prefixes), evidence)


def guard_from_arg(content: str, start: int, end: int, context: str | None = None) -> Guard | None:
    """A Guard when the middleware argument at ``content[start:end]`` authenticates."""
    end = min(end, start + _ARG_SCAN)
    match = _ARG_NAME.match(content, start, end)
    if not match:
        return None
    name = match.group(1)
    if not _AUTH_NAME.search(name) or _NOT_A_GUARD.search(name):
        return None
    text = content[start:end]
    evidence = clip(context if context is not None else text)
    skipper = _skipper(content, start, end)
    call_open = content.find("(", match.end(), end)
    literal_config = "{" in text
    uncertain = bool(_CONFIG_CTOR.search(name)) and call_open >= 0 and not literal_config and bool(
        content[call_open + 1 : end].strip(" \t\n)")
    )
    return Guard(name, evidence, skipper, uncertain)


# A handler wrapped in middleware: `requireAuth(h)`, `authMW(h)`,
# `auth.Middleware(h)`, `jwtMiddleware.Handler(h)`. The called name (the last
# dotted segment) must be middleware-shaped, or be `Handler` / `Wrap` on a
# middleware-named receiver, so a handler constructor such as
# `auth.LoginHandler(db)`, `authMW.LoginHandler(db)` or
# `oauthMiddleware.Callback(cb)` isn't mistaken for a guard.
_WRAPPER_SEGMENT = re.compile(
    r"(?:\w*(?:middleware|mw|required|guard|protect(?:ed)?|wrap(?:per)?)"
    r"|(?:require|ensure|must|with|verify|check|authenticated?|protect)\w*)$",
    re.IGNORECASE,
)
_WRAPPER_METHOD = re.compile(r"(?:Handler|HandlerFunc|Wrap|WrapHandler)$")
_MIDDLEWARE_RECEIVER = re.compile(r"\w*(?:middleware|mw)$", re.IGNORECASE)
_CALL_NAME = re.compile(r"\s*([A-Za-z_][\w.]*)\s*\(")


def _wrapper_shaped(name: str) -> bool:
    segments = name.split(".")
    if _WRAPPER_SEGMENT.match(segments[-1]):
        return True
    return len(segments) > 1 and bool(_WRAPPER_METHOD.match(segments[-1])) and bool(
        _MIDDLEWARE_RECEIVER.match(segments[-2])
    )


def wrapper_guard(content: str, start: int, end: int, context: str) -> Guard | None:
    """A Guard when the handler argument ``content[start:end]`` is an auth
    middleware call wrapping the handler."""
    match = _CALL_NAME.match(content, start, end)
    if not match or match.group(1) == "func":
        return None
    close = matching_close(content, match.end() - 1)
    if close < 0 or close >= end or not content[match.end() : close].strip():
        return None
    if not _wrapper_shaped(match.group(1)):
        return None
    return guard_from_arg(content, start, end, context)


# ---------- Router bindings ----------


@dataclass
class Binding:
    name: str
    offset: int
    scope: tuple[int, int]
    parent: "Binding | None" = None
    prefix: str | None = ""  # path prefix relative to the parent; None: not a literal
    guards: list[Guard] = field(default_factory=list)  # added where it was derived
    root: bool = False  # a constructor (gin.Default(), chi.NewRouter(), ...)
    uses: list[tuple[int, list[Guard]]] = field(default_factory=list)
    overflow: bool = False
    # Where it hangs off its parent: the parent's `Use` calls before this
    # offset apply. Its own offset, or the `Mount` / `Route` call's.
    link: int = -1
    # The latest earlier binding of the same name in an outer block that
    # contains this one's offset: where a lookup goes once this scope closed.
    enclosing: "Binding | None" = None
    # Mounted under more than one parent: its auth can't be resolved.
    ambiguous: bool = False

    def __post_init__(self) -> None:
        if self.link < 0:
            self.link = self.offset


_MAX_USES = 16
# A path literal: interpreted (no escapes) or raw, on one line.
LIT = r"(?:\"([^\"\\\n]{0,512})\"|`([^`\n]{0,512})`)"

_ROOT = re.compile(
    r"\b(\w+)\s*:?=\s*(?:gin\s*\.\s*(?:Default|New)|echo\s*\.\s*New|fiber\s*\.\s*New"
    r"|chi\s*\.\s*(?:NewRouter|NewMux)|mux\s*\.\s*NewRouter|http\s*\.\s*NewServeMux)\s*\("
)
_DERIVED = re.compile(r"\b(\w+)\s*:?=\s*(\w+)\s*\.\s*(Group|With)\s*\(")
# gorilla `api := r.PathPrefix("/api").Subrouter()`: the chain is walked to its
# `.Subrouter()`.
_SUBROUTER = re.compile(
    r"\b(\w+)\s*:?=\s*(\w+)(?=\s*\.\s*(?:PathPrefix|Host|Methods|Schemes|Headers|Queries"
    r"|NewRoute|MatcherFunc)\s*\()"
)
# chi `r.Route("/x", func(r chi.Router) {` / `r.Group(func(r chi.Router) {`,
# fiber `app.Route("/x", func(api fiber.Router) {`, and the parameterless
# closure of a router that keeps a group stack (gitea's `m.Group("/x", func() {`),
# where the closure registers on the receiver itself.
_CLOSURE = re.compile(
    r"\b(\w+)\s*\.\s*(Group|Route)\s*\(\s*(?:" + LIT + r"\s*,\s*)?"
    r"func\s*\(\s*(?:(\w+)\s+[\w.*]+\s*)?\)\s*\{"
)
# chi / fiber `r.Mount("/admin", sub)` / `r.Mount("/admin", adminRouter())` /
# `r.Mount("/admin", h.Routes())`, and chi `r.Route("/admin", adminRoutes)`.
_MOUNT = re.compile(
    r"\b(\w+)\s*\.\s*(Mount|Route)\s*\(\s*" + LIT + r"\s*,\s*(\w+)(?:\s*\.\s*(\w+))?\s*(?:(\()|(?=[,)]))"
)
# Function and method declarations, with the first parameter's name.
_FUNC_DEF = re.compile(
    r"^func[ \t]+(\([^()\n]{0,200}\)[ \t]*)?(\w+)\s*(?:\[[^\]\n]{0,200}\]\s*)?\(\s*(?:(\w+)\s+[\w.*\[\]]+\s*[,)])?",
    re.MULTILINE,
)
_USE = re.compile(r"\b(\w+)\s*\.\s*Use\s*\(")
# Identifiers, for checking how a mounted router (or the function that builds
# it) is used elsewhere in the file; a method call on it (`sub.Get(`) is fine.
_IDENT = re.compile(r"[A-Za-z_]\w*")
_METHOD_CALL = re.compile(r"\s*\.\s*(\w+)\s*\(")
_RETURN_BEFORE = re.compile(r"\breturn\s+$")
_SELECTOR_BEFORE = re.compile(r"\.\s*$")
# Identifier occurrences checked per file before giving up; mounted routers
# not yet cleared are then treated as ambiguous.
_MAX_MOUNT_USES = 20000
# Mounted-router scopes checked around one occurrence (sibling scopes before
# it have closed; this bounds nested ones).
_MAX_NESTED_SCOPES = 8

# chi `r.With(mw...).Route("/x", func(r chi.Router) {...})` / `.Group(func(r chi.Router) {...})`:
# a closure router carrying the inline middleware. The chain is walked from `.With(`.
_WITH = re.compile(r"\b(\w+)\s*\.\s*With\s*\(")
_FUNC_PARAM = re.compile(r"\s*func\s*\(\s*(\w+)\s+[\w.*]+\s*\)\s*\{")


@dataclass
class Resolution:
    auth: str = UNKNOWN
    guards: list[str] = field(default_factory=list)
    evidence: str | None = None
    # The route's path joined with every literal prefix above it, up to the
    # first one that isn't a literal (or the router's root).
    path: str | None = None


class FileRouters:
    """Router variables, their derivations and ``Use`` calls in one file."""

    def __init__(self, content: str) -> None:
        self.content = content
        pairs = bracket_pairs(content)
        self._blocks = sorted((o, c) for o, c in pairs.items() if content[o] == "{")
        # Top-level blocks (function bodies), for routers passed in as parameters.
        self._top: list[tuple[int, int]] = []
        for block in self._blocks:
            if not self._top or block[0] > self._top[-1][1]:
                self._top.append(block)
        self._top_starts = [start for start, _ in self._top]
        self._by_name: dict[str, list[Binding]] = {}
        self._offsets: dict[str, list[int]] = {}
        self._free: dict[tuple[str, int], Binding] = {}
        # Mounted routers to check for other uses: (target, the mount's
        # argument span, variable name or None, builder function name or None,
        # the function name's offset in its declaration).
        self._mounted: list[tuple[Binding, tuple[int, int], str | None, str | None, int, bool]] = []
        self._roots: list[Binding] = []  # in offset order
        self._root_offsets: list[int] = []
        self._funcs: dict[tuple[str, bool], list[re.Match]] | None = None
        mounts: list[re.Match] = []
        # Sweep state: blocks open at the current event offset.
        self._stack: list[tuple[int, int]] = []
        self._next_block = 0
        events: list[tuple[int, int, re.Match]] = []
        for kind, pattern in enumerate((_ROOT, _DERIVED, _SUBROUTER, _CLOSURE, _USE, _MOUNT, _WITH)):
            events += [(m.start(), kind, m) for m in pattern.finditer(content)]
        events.sort(key=lambda e: (e[0], e[1]))
        for offset, kind, match in events:
            scope = self._advance(offset)
            if kind == 0:
                binding = Binding(match.group(1), offset, scope, root=True)
                self._roots.append(binding)
                self._root_offsets.append(offset)
                self._bind(binding)
            elif kind == 1:
                self._derive(match, scope)
            elif kind == 2:
                self._subrouter(match, scope)
            elif kind == 3:
                self._closure(match)
            elif kind == 4:
                self._use(match)
            elif kind == 5:
                mounts.append(match)
            else:
                self._with_closure(match)
        # Mounted routers are often built after the call, in a later function.
        for match in mounts:
            self._mount(match)
        self._check_mounted_uses()

    # -- scopes --

    def _advance(self, offset: int) -> tuple[int, int]:
        """Innermost block containing ``offset``; offsets arrive ascending, so
        each block is pushed and popped once."""
        while self._next_block < len(self._blocks) and self._blocks[self._next_block][0] < offset:
            block = self._blocks[self._next_block]
            self._next_block += 1
            while self._stack and self._stack[-1][1] < block[0]:
                self._stack.pop()
            self._stack.append(block)
        while self._stack and self._stack[-1][1] < offset:
            self._stack.pop()
        return self._stack[-1] if self._stack else (0, len(self.content))

    def _top_level(self, offset: int) -> tuple[int, int]:
        index = bisect.bisect_right(self._top_starts, offset) - 1
        if index >= 0 and self._top[index][1] >= offset:
            return self._top[index]
        return (0, len(self.content))

    # -- bindings --

    def _bind(self, binding: Binding) -> None:
        offsets = self._offsets.setdefault(binding.name, [])
        bindings = self._by_name.setdefault(binding.name, [])
        index = bisect.bisect_right(offsets, binding.offset)
        candidate = bindings[index - 1] if index else None
        for _ in range(_LOOKUP_LIMIT):
            if candidate is None or (
                candidate.scope != binding.scope and candidate.scope[0] <= binding.offset <= candidate.scope[1]
            ):
                break
            candidate = candidate.enclosing
        else:
            candidate = None
        binding.enclosing = candidate
        offsets.insert(index, binding.offset)
        bindings.insert(index, binding)

    def _free_binding(self, name: str, scope: tuple[int, int]) -> Binding:
        free = self._free.get((name, scope[0]))
        if free is None:
            free = self._free[(name, scope[0])] = Binding(name, scope[0], scope)
        return free

    def resolve(self, name: str, offset: int) -> Binding | None:
        """The binding of ``name`` visible at ``offset``: the latest earlier
        assignment whose block contains it, else a free binding for the
        enclosing top-level function (a router passed in as a parameter).
        None when the bounded search gives up."""
        bindings = self._by_name.get(name, [])
        index = bisect.bisect_left(self._offsets.get(name, []), offset) - 1
        binding = bindings[index] if index >= 0 else None
        for _ in range(_LOOKUP_LIMIT):
            if binding is None:
                break
            if binding.scope[0] <= offset <= binding.scope[1]:
                return binding
            # Its block closed before `offset`; a binding that is visible here
            # is in an outer block, so climb those rather than every sibling.
            binding = binding.enclosing
        else:
            return None
        return self._free_binding(name, self._top_level(offset))

    def _call(self, paren: int) -> tuple[list[tuple[int, int]], int] | None:
        """Top-level argument spans and the closing offset for the ``(`` at ``paren``."""
        close = matching_close(self.content, paren)
        if close < 0:
            return None
        return split_args(self.content, paren, close), close

    def _context(self, start: int, close: int) -> str:
        return self.content[start : min(close + 1, start + 2 * _EVIDENCE_MAX)]

    def _derive(self, match: re.Match, scope: tuple[int, int]) -> None:
        parent = self.resolve(match.group(2), match.start())
        call = self._call(match.end() - 1)
        if parent is None or call is None:
            return
        args, close = call
        prefix: str | None = ""
        if match.group(3) == "Group":
            first = string_literal(self.content[args[0][0] : args[0][1]]) if args else None
            prefix, args = first, args[1:]
        context = self._context(match.start(), close)
        guards = [g for s, e in args if (g := guard_from_arg(self.content, s, e, context))]
        self._bind(Binding(match.group(1), match.start(), scope, parent, prefix, guards))

    def _subrouter(self, match: re.Match, scope: tuple[int, int]) -> None:
        segments = walk_chain(self.content, match.end())
        names = [name for name, _, _ in segments]
        if "Subrouter" not in names:
            return
        prefix: str | None = ""
        for name, open_idx, close in segments[: names.index("Subrouter")]:
            if name != "PathPrefix":
                continue
            args = split_args(self.content, open_idx, close)
            literal = string_literal(self.content[args[0][0] : args[0][1]]) if len(args) == 1 else None
            prefix = None if prefix is None or literal is None else join_paths(prefix, literal)
        parent = self.resolve(match.group(2), match.start())
        if parent is not None:
            self._bind(Binding(match.group(1), match.start(), scope, parent, prefix))

    def _closure(self, match: re.Match) -> None:
        parent = self.resolve(match.group(1), match.start())
        body_open = match.end() - 1
        body_close = matching_close(self.content, body_open)
        if parent is None or body_close < 0:
            return
        literal = match.group(3) if match.group(3) is not None else match.group(4)
        # A parameterless closure (gitea's `m.Group("/x", func() {...}, mw...)`)
        # registers on the receiver itself. Its trailing middleware belongs to
        # a project's own wrapper whose semantics we can't read (gitea's
        # `checkTokenPublicOnly()` restricts tokens, `webAuth.AllowBasic` only
        # permits a scheme), so the group contributes its prefix, not guards.
        name = match.group(5) or match.group(1)
        self._bind(Binding(name, body_open, (body_open, body_close), parent, literal or ""))

    def _with_closure(self, match: re.Match) -> None:
        segments = walk_chain(self.content, match.start(1) + len(match.group(1)))
        if len(segments) < 2 or segments[-1][0] not in ("Route", "Group"):
            return
        if any(name != "With" for name, _, _ in segments[:-1]):
            return
        parent = self.resolve(match.group(1), match.start())
        if parent is None:
            return
        guards: list[Guard] = []
        for _, open_idx, close in segments[:-1]:
            context = self._context(match.start(), close)
            args = split_args(self.content, open_idx, close)
            guards += [g for s, e in args if (g := guard_from_arg(self.content, s, e, context))]
        name, open_idx, close = segments[-1]
        args = split_args(self.content, open_idx, close)
        prefix: str | None = ""
        if name == "Route":
            if len(args) != 2:
                return
            prefix = string_literal(self.content[args[0][0] : args[0][1]])
        elif len(args) != 1:
            return
        func = _FUNC_PARAM.match(self.content, args[-1][0], args[-1][1])
        if not func:
            return
        body_open = func.end() - 1
        body_close = matching_close(self.content, body_open)
        if body_close >= 0:
            self._bind(Binding(func.group(1), body_open, (body_open, body_close), parent, prefix, guards))

    def _use(self, match: re.Match) -> None:
        binding = self.resolve(match.group(1), match.start())
        call = self._call(match.end() - 1)
        if binding is None or call is None:
            return
        args, close = call
        prefix = None
        if args and (literal := string_literal(self.content[args[0][0] : args[0][1]])) is not None:
            prefix, args = literal, args[1:]
        context = self._context(match.start(), close)
        guards = [g for s, e in args if (g := guard_from_arg(self.content, s, e, context))]
        if not guards:
            return
        for guard in guards:
            guard.prefix = prefix
        if len(binding.uses) >= _MAX_USES:
            binding.overflow = True
            return
        binding.uses.append((match.start(), guards))

    # -- mounts --

    def _function(self, name: str, method: bool) -> tuple[re.Match, tuple[int, int]] | None:
        """The one declaration of function (or method) ``name`` in this file
        and its body block; None when there are none or several."""
        key = (name, method)
        if self._funcs is None:
            self._funcs = {}
            for match in _FUNC_DEF.finditer(self.content):
                self._funcs.setdefault((match.group(2), match.group(1) is not None), []).append(match)
        found = self._funcs.get(key, [])  # keyed by (name, method): no rescan per lookup
        if len(found) != 1:
            return None
        index = bisect.bisect_left(self._top_starts, found[0].end())
        if index >= len(self._top):
            return None
        return found[0], self._top[index]

    def _mount(self, match: re.Match) -> None:
        kind, first, second, call = match.group(2), match.group(5), match.group(6), match.group(7)
        if first == "func":
            return
        target: Binding | None = None
        variable: str | None = None
        function: str | None = None
        function_offset = -1
        method = False
        if kind == "Mount" and call is None and second is None:
            # r.Mount("/admin", sub): a router built in this file.
            target = self.resolve(first, match.start())
            if target is None or not target.root:
                return
            variable = first
        elif kind == "Mount" and call is not None:
            # r.Mount("/admin", adminRouter()): the one router that function builds.
            found = self._function(second or first, second is not None)
            if found is None:
                return
            body = found[1]
            first = bisect.bisect_right(self._root_offsets, body[0])
            if bisect.bisect_left(self._root_offsets, body[1]) - first != 1:
                return
            target = self._roots[first]
            variable, function, function_offset = target.name, found[0].group(2), found[0].start(2)
            method = second is not None
        elif kind == "Route" and call is None:
            # r.Route("/admin", adminRoutes): the function's router parameter.
            found = self._function(second or first, second is not None)
            if found is None or found[0].group(3) is None:
                return
            target = self._free_binding(found[0].group(3), found[1])
            function, function_offset = found[0].group(2), found[0].start(2)
            method = second is not None
        if target is None:
            return
        parent = self.resolve(match.group(1), match.start())
        if parent is None:
            return
        node: Binding | None = parent
        for _ in range(_MAX_DEPTH):  # never into its own subtree
            if node is None:
                break
            if node is target:
                return
            node = node.parent
        literal = match.group(3) if match.group(3) is not None else match.group(4)
        if target.parent is not None:
            # Mounted twice: reachable under either parent, so neither its
            # prefix nor the parents' middleware is known.
            target.prefix, target.ambiguous = None, True
            return
        target.parent, target.prefix, target.link = parent, literal, match.start()
        paren = self.content.find("(", match.end(2))
        close = matching_close(self.content, paren)
        args = split_args(self.content, paren, close) if close >= 0 else []
        span = args[1] if len(args) >= 2 else (match.start(), match.end())
        self._mounted.append((target, span, variable, function, function_offset, method))

    def _check_mounted_uses(self) -> None:
        """A mounted router whose name is used for anything but its own method
        calls (`sub.Get(...)`, `sub.Use(...)`) and the mount itself may be
        served another way: `http.ListenAndServe(addr, sub)`, `http.Serve(ln,
        sub)`, `srv.Handler = sub`, `handlers.LoggingHandler(w, sub)`,
        `mux.HandleFunc("/", sub.ServeHTTP)`. Likewise a builder function
        used again. Either way the router is reachable without the parent's
        middleware: ambiguous (auth unknown, its own path)."""
        # Functions / methods by name -> (target, mount argument span, is a
        # method, declaration offset). Variables by name -> entries sorted by
        # scope start, so an occurrence only checks the scopes around it.
        functions: dict[str, list[tuple[Binding, tuple[int, int], bool, int]]] = {}
        variables: dict[str, list[tuple[int, Binding, tuple[int, int]]]] = {}
        for target, span, variable, function, function_offset, method in self._mounted:
            if variable is not None:
                variables.setdefault(variable, []).append((target.scope[0], target, span))
            if function is not None:
                functions.setdefault(function, []).append((target, span, method, function_offset))
        if not functions and not variables:
            return
        scope_starts: dict[str, list[int]] = {}
        for name, entries in variables.items():
            entries.sort(key=lambda entry: entry[0])
            scope_starts[name] = [entry[0] for entry in entries]
        content = self.content
        seen = 0
        for match in _IDENT.finditer(content):
            name = match.group()
            if name not in functions and name not in variables:
                continue
            seen += 1
            if seen > _MAX_MOUNT_USES:
                for target, *_ in self._mounted:
                    target.prefix, target.ambiguous = None, True
                return
            offset = match.start()
            if in_literal(content, offset):
                continue
            selector = _SELECTOR_BEFORE.search(content, max(0, offset - 16), offset) is not None
            for target, span, method, declared in functions.get(name, ()):
                # A method is used as `x.name`, a function as a bare name; the
                # other spelling is something else of the same name.
                if target.ambiguous or span[0] <= offset < span[1] or offset == declared or selector != method:
                    continue
                target.prefix, target.ambiguous = None, True
            entries = variables.get(name)
            if not entries or selector:
                continue  # `x.sub` is another value's field
            index = bisect.bisect_right(scope_starts[name], offset) - 1
            for _ in range(_MAX_NESTED_SCOPES):  # the (few) scopes that can contain it
                if index < 0:
                    break
                _, target, span = entries[index]
                index -= 1
                if target.ambiguous or span[0] <= offset < span[1] or offset == target.offset:
                    continue
                if not target.scope[0] <= offset <= target.scope[1]:
                    continue
                call = _METHOD_CALL.match(content, match.end())
                if call and call.group(1) != "ServeHTTP":
                    continue
                if _RETURN_BEFORE.search(content, max(0, offset - 16), offset):
                    continue  # a builder returning it to the mount
                target.prefix, target.ambiguous = None, True

    # -- resolution --

    def is_router(self, text: str, offset: int) -> bool:
        """``text`` is a router variable built in this file (``r`` in
        ``http.Handle("/", r)``), not a handler."""
        name = text.strip()
        if not name.isidentifier():
            return False
        binding = self.resolve(name, offset)
        return binding is not None and (binding.root or binding.parent is not None)

    def resolve_route(
        self, receiver: str, offset: int, path: str, local: list[Guard] | None, *, ordered: bool = True
    ) -> Resolution:
        """The route's auth and joined path. ``local`` is the route's own
        middleware, None when its arguments couldn't be read (auth unknown).
        ``ordered``: a ``Use`` applies only to routes registered after it
        (gin, echo, fiber, chi); gorilla applies it to every route."""
        binding = self.resolve(receiver, offset)
        if binding is None:
            return Resolution(path=path)
        auth_known = local is not None
        applied: list[Guard] = list(local or [])
        rel_path: str | None = path  # relative to the binding being walked
        known = path
        position = offset
        top = binding
        for _ in range(_MAX_DEPTH):
            if binding.overflow or binding.ambiguous:
                auth_known = False
            for use_offset, guards in binding.uses if auth_known else ():
                if ordered and use_offset >= position:
                    continue
                for guard in guards:
                    if guard.prefix is None:
                        applied.append(guard)
                    elif rel_path is None:
                        applied.append(Guard(guard.name, guard.evidence, uncertain=True))
                    elif rel_path.startswith(guard.prefix):
                        applied.append(guard)
            applied.extend(binding.guards)
            if rel_path is not None:
                rel_path = None if binding.prefix is None else join_paths(binding.prefix, rel_path)
                known = rel_path if rel_path is not None else known
            position = binding.link
            top = binding
            if binding.parent is None:
                break
            binding = binding.parent
        else:
            # Derivation deeper than _MAX_DEPTH: the prefix is unknown. The
            # route's own path, not a partial join that two routes at
            # different depths could share.
            return Resolution(path=path)
        if not auth_known:
            return Resolution(path=known)
        resolution = evaluate(applied, rel_path if top.root else None)
        resolution.path = known
        return resolution


def evaluate(guards: list[Guard], full_path: str | None) -> Resolution:
    required: list[Guard] = []
    skipped: list[Guard] = []
    uncertain = False
    for guard in guards:
        if guard.uncertain:
            uncertain = True
        elif guard.skipper is None:
            required.append(guard)
        elif not guard.skipper.characterized or full_path is None:
            uncertain = True
        elif guard.skipper.skips(full_path):
            skipped.append(guard)
        else:
            required.append(guard)
    if required:
        names = list(dict.fromkeys(g.name for g in required))
        return Resolution(REQUIRED, names, clip("; ".join(dict.fromkeys(g.evidence for g in required))))
    if uncertain:
        return Resolution()
    if skipped:
        evidence = "; ".join(dict.fromkeys(g.skipper.evidence for g in skipped if g.skipper))
        return Resolution(ANONYMOUS, [], clip(evidence))
    return Resolution()
