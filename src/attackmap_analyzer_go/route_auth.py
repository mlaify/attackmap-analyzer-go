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
  ``g := r.With(mw...)`` (chi), and closure routers
  ``r.Group(func(r chi.Router) {...})`` / ``r.Route("/x", func(r chi.Router)
  {...})``, which inherit the parent's middleware;
- ``X.Use(mw...)`` applies to routes registered on ``X`` (or routers derived
  from it) after the call, which is how gin, echo groups and fiber behave and
  the only order chi allows; fiber ``X.Use("/prefix", mw)`` only to paths
  under the prefix;
- route-local middleware: gin / fiber ``r.POST("/x", mw..., h)``, echo
  ``e.POST("/x", h, mw...)`` and chi ``r.With(mw...).Post("/x", h)``.

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
split by jumping over nested brackets, and lookups are bounded.
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
# Bindings of one name searched before giving up (the route stays unknown).
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


_STRING_LITERAL = re.compile(r'\s*"([^"\\]*)"\s*$')


def string_literal(text: str) -> str | None:
    match = _STRING_LITERAL.match(text)
    return match.group(1) if match else None


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


_MAX_USES = 16

_ROOT = re.compile(
    r"\b(\w+)\s*:?=\s*(?:gin\s*\.\s*(?:Default|New)|echo\s*\.\s*New|fiber\s*\.\s*New"
    r"|chi\s*\.\s*(?:NewRouter|NewMux))\s*\("
)
_DERIVED = re.compile(r"\b(\w+)\s*:?=\s*(\w+)\s*\.\s*(Group|With)\s*\(")
_CLOSURE = re.compile(
    r"\b(\w+)\s*\.\s*(Group|Route)\s*\(\s*(?:\"([^\"\\]*)\"\s*,\s*)?func\s*\(\s*(\w+)\s+[\w.*]+\s*\)\s*\{"
)
_USE = re.compile(r"\b(\w+)\s*\.\s*Use\s*\(")


@dataclass
class Resolution:
    auth: str = UNKNOWN
    guards: list[str] = field(default_factory=list)
    evidence: str | None = None


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
        # Sweep state: blocks open at the current event offset.
        self._stack: list[tuple[int, int]] = []
        self._next_block = 0
        events: list[tuple[int, int, re.Match]] = []
        for kind, pattern in enumerate((_ROOT, _DERIVED, _CLOSURE, _USE)):
            events += [(m.start(), kind, m) for m in pattern.finditer(content)]
        events.sort(key=lambda e: (e[0], e[1]))
        for offset, kind, match in events:
            scope = self._advance(offset)
            if kind == 0:
                self._bind(Binding(match.group(1), offset, scope, root=True))
            elif kind == 1:
                self._derive(match, scope)
            elif kind == 2:
                self._closure(match)
            else:
                self._use(match)

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
        index = bisect.bisect_right(offsets, binding.offset)
        offsets.insert(index, binding.offset)
        self._by_name.setdefault(binding.name, []).insert(index, binding)

    def resolve(self, name: str, offset: int) -> Binding | None:
        """The binding of ``name`` visible at ``offset``: the latest earlier
        assignment whose block contains it, else a free binding for the
        enclosing top-level function (a router passed in as a parameter).
        None when the bounded search gives up."""
        bindings = self._by_name.get(name, [])
        index = bisect.bisect_left(self._offsets.get(name, []), offset) - 1
        for _ in range(_LOOKUP_LIMIT):
            if index < 0:
                break
            binding = bindings[index]
            if binding.scope[0] <= offset <= binding.scope[1]:
                return binding
            index -= 1
        else:
            if index >= 0:
                return None
        scope = self._top_level(offset)
        free = self._free.get((name, scope[0]))
        if free is None:
            free = self._free[(name, scope[0])] = Binding(name, scope[0], scope)
        return free

    def _call(self, paren: int) -> tuple[list[tuple[int, int]], str] | None:
        """Top-level argument spans and clipped call text for the ``(`` at ``paren``."""
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

    def _closure(self, match: re.Match) -> None:
        parent = self.resolve(match.group(1), match.start())
        body_open = match.end() - 1
        body_close = matching_close(self.content, body_open)
        if parent is None or body_close < 0:
            return
        prefix = match.group(3) if match.group(3) is not None else ""
        self._bind(Binding(match.group(4), body_open, (body_open, body_close), parent, prefix))

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

    # -- resolution --

    def resolve_route(self, receiver: str, offset: int, path: str, local: list[Guard]) -> Resolution:
        binding = self.resolve(receiver, offset)
        if binding is None:
            return Resolution()
        applied: list[Guard] = list(local)
        rel_path: str | None = path  # relative to the binding being walked
        position = offset
        top = binding
        for _ in range(_MAX_DEPTH):
            if binding.overflow:
                return Resolution()
            for use_offset, guards in binding.uses:
                if use_offset >= position:
                    continue
                for guard in guards:
                    if guard.prefix is None:
                        applied.append(guard)
                    elif rel_path is None:
                        applied.append(Guard(guard.name, guard.evidence, uncertain=True))
                    elif rel_path.startswith(guard.prefix):
                        applied.append(guard)
            applied.extend(binding.guards)
            rel_path = None if rel_path is None or binding.prefix is None else binding.prefix + rel_path
            position = binding.offset
            top = binding
            if binding.parent is None:
                break
            binding = binding.parent
        else:
            return Resolution()  # derivation deeper than _MAX_DEPTH
        return evaluate(applied, rel_path if top.root else None)


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
