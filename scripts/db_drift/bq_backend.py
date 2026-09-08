"""BigQuery backends behind one interface.

Backend is the protocol the schema, security, load, and validate modules
call. LiveBackend shells out to the bq and gcloud CLIs, except for
creating taxonomies and policy tags and deleting taxonomies: gcloud has
no such verbs (its taxonomies group offers describe, list, import,
export, and IAM only, and import cannot add a tag to an existing
taxonomy), so those three calls go to the Data Catalog REST API with a
token minted by gcloud. Everything is written from the CLI and API
documentation and mock-tested through fake runners; it is not
live-tested in this repository. EmulatedBackend keeps a JSON model
of datasets, tables, IAM, policy tags, and row access policies on disk
plus the loaded NDJSON rows, and enforces the structural rules the
pipeline relies on: a tagged column is readable only with the
fine-grained reader role on its tag, a table with any row access policy
denies rows to principals no policy names, and simple predicates are
evaluated against loaded rows. Anything the emulator cannot evaluate is
reported as unevaluable, never as a pass.

Every mutating call on either backend appends one JSON line to the
OperationLog. Access tokens are passed to bq in argv only and are
redacted before anything is logged.
"""
import argparse
import collections
import gzip
import importlib
import json
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from db_drift import config, pg

ROLE_VIEWER = "roles/bigquery.dataViewer"
ROLE_EDITOR = "roles/bigquery.dataEditor"
ROLE_OWNER = "roles/bigquery.dataOwner"
ROLE_ADMIN = "roles/bigquery.admin"
ROLE_META = "roles/bigquery.metadataViewer"
ROLE_JOBUSER = "roles/bigquery.jobUser"
ROLE_FGR = "roles/datacatalog.categoryFineGrainedReader"

# Legacy dataset access roles as bq show reports them.
LEGACY_ROLES = {"READER": ROLE_VIEWER, "WRITER": ROLE_EDITOR,
                "OWNER": ROLE_OWNER}
# Roles that let a principal read table data at whatever scope they are
# granted. metadataViewer and jobUser deliberately are not in this set.
DATA_READ_ROLES = {ROLE_VIEWER, ROLE_EDITOR, ROLE_OWNER, ROLE_ADMIN}
FORBIDDEN_MEMBERS = ("allUsers", "allAuthenticatedUsers")
# The only specialGroup values bq accepts besides the two forbidden ones.
PROJECT_SPECIAL_GROUPS = ("projectOwners", "projectReaders", "projectWriters")
_MEMBER_KIND_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
_MEMBER_BAD_CHARS_RE = re.compile(r"[\s\"'`\\\x00-\x1f]")
MIGRATION_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
TAXONOMY_NAME_RE = re.compile(
    r"^projects/([^/]+)/locations/([^/]+)/taxonomies/([^/]+)$")
DATACATALOG_API = "https://datacatalog.googleapis.com/v1"
# bq ls returns 50 items unless told otherwise; a real schema has more.
BQ_LS_MAX_RESULTS = 10000

TYPE_ALIASES = {"INTEGER": "INT64", "FLOAT": "FLOAT64", "BOOLEAN": "BOOL",
                "DECIMAL": "NUMERIC", "BIGDECIMAL": "BIGNUMERIC"}
KNOWN_TYPES = {"INT64", "FLOAT64", "NUMERIC", "BIGNUMERIC", "BOOL", "STRING",
               "BYTES", "DATE", "DATETIME", "TIME", "TIMESTAMP", "JSON",
               "GEOGRAPHY", "INTERVAL", "RANGE"}
IDENT_RE = re.compile(r"^[A-Za-z0-9_]+$")
STATE_FILE = "state.json"


class BackendError(Exception):
    pass


class Unevaluable(Exception):
    """The emulator cannot evaluate this predicate; never guess a count."""


class SqlSyntaxError(Exception):
    pass


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------ OperationLog

class OperationLog:
    def __init__(self, path):
        self.path = Path(path) if path else None

    def record(self, op, **details):
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"ts": _now(), "op": op}
        entry.update(details)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")


# ------------------------------------------------------------ SQL tokens

Token = collections.namedtuple("Token", "kind text start end")
_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER_RE = re.compile(r"\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?")
_TWO_CHAR_OPS = ("<>", "!=", "<=", ">=", "||")
# An optional r, b, rb, or br prefix followed by the opening quote.
_STRING_START_RE = re.compile(r"(?i)(rb|br|r|b)?(['\"])")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "a": "\a",
            "b": "\b", "f": "\f", "v": "\v"}


def _read_string(sql, quote_at, raw):
    """Read the literal whose opening quote sits at quote_at.

    Handles single and triple quotes and backslash escapes. In a raw
    literal the backslash is kept and still protects the next character,
    so r'\\'' does not end at the inner quote. Returns (text, end).
    """
    q = sql[quote_at]
    n = len(sql)
    close = q * 3 if sql.startswith(q * 3, quote_at) else q
    j = quote_at + len(close)
    buf = []
    while j < n:
        if sql.startswith(close, j):
            return "".join(buf), j + len(close)
        c = sql[j]
        if c == "\\" and j + 1 < n:
            nxt = sql[j + 1]
            buf.append(c + nxt if raw else _ESCAPES.get(nxt, nxt))
            j += 2
            continue
        buf.append(c)
        j += 1
    raise SqlSyntaxError("unterminated string literal")


def tokenize_sql(sql):
    """Split SQL into tokens with source positions.

    Kinds: word, ident (backticked, text without the backticks), string
    (text unescaped; raw literals keep their backslashes), bytes (a b or
    rb prefixed literal), number, op (two-character operators), punct
    (one character). Comments are dropped. Triple-quoted literals are
    read as one token. Two adjacent literals stay two tokens, as BigQuery
    has no doubled-quote escape. A bare identifier outside [A-Za-z0-9_]
    is a syntax error, as it is in BigQuery.
    """
    tokens = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch.isspace():
            i += 1
            continue
        if sql.startswith("--", i) or sql.startswith("#", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            if j < 0:
                raise SqlSyntaxError("unterminated block comment")
            i = j + 2
            continue
        if ch == "`":
            j = sql.find("`", i + 1)
            if j < 0:
                raise SqlSyntaxError("unterminated backtick identifier")
            tokens.append(Token("ident", sql[i + 1:j], i, j + 1))
            i = j + 1
            continue
        m = _STRING_START_RE.match(sql, i) if ch in "'\"rRbB" else None
        if m:
            prefix = (m.group(1) or "").lower()
            text, end = _read_string(sql, m.start(2), "r" in prefix)
            tokens.append(Token("bytes" if "b" in prefix else "string",
                                text, i, end))
            i = end
            continue
        if ch.isdigit() or (ch == "." and i + 1 < n and sql[i + 1].isdigit()):
            m = _NUMBER_RE.match(sql, i)
            tokens.append(Token("number", m.group(0), i, m.end()))
            i = m.end()
            continue
        if ch.isalpha() or ch == "_":
            m = _WORD_RE.match(sql, i)
            if m is None:
                raise SqlSyntaxError(
                    f"unsupported character {ch!r} at offset {i}; bare "
                    "identifiers use [A-Za-z0-9_], anything else needs "
                    "backticks")
            tokens.append(Token("word", m.group(0), i, m.end()))
            i = m.end()
            continue
        two = sql[i:i + 2]
        if two in _TWO_CHAR_OPS:
            tokens.append(Token("op", two, i, i + 2))
            i += 2
            continue
        tokens.append(Token("punct", ch, i, i + 1))
        i += 1
    return tokens


def _match_paren(tokens, idx):
    """Index of the ')' matching the '(' at idx."""
    depth = 0
    for j in range(idx, len(tokens)):
        t = tokens[j]
        if t.kind == "punct" and t.text == "(":
            depth += 1
        elif t.kind == "punct" and t.text == ")":
            depth -= 1
            if depth == 0:
                return j
    raise SqlSyntaxError("unbalanced parentheses")


def split_statements(sql):
    """Return [(statement_text, tokens)] for a script; ';' separates.

    Token offsets are rebased so they index into statement_text, not the
    whole script; the DDL parser slices view bodies and policy filters
    out of statement_text with them.
    """
    tokens = tokenize_sql(sql)
    out, current = [], []

    def flush():
        base = current[0].start
        text = sql[base:current[-1].end]
        rebased = [Token(t.kind, t.text, t.start - base, t.end - base)
                   for t in current]
        out.append((text, rebased))

    for tok in tokens:
        if tok.kind == "punct" and tok.text == ";":
            if current:
                flush()
            current = []
        else:
            current.append(tok)
    if current:
        flush()
    return out


# ------------------------------------------------------ predicate evaluator

_PREDICATE_KEYWORDS = {"AND", "OR", "NOT", "IN", "TRUE", "FALSE", "NULL",
                       "IS", "LIKE", "BETWEEN", "EXISTS", "SELECT", "CASE",
                       "SESSION_USER"}


class _PredicateParser:
    """Recursive descent over the small predicate subset the emulator
    understands. Anything outside it raises Unevaluable."""

    def __init__(self, tokens, columns):
        self.toks = tokens
        self.columns = columns
        self.pos = 0

    def peek(self, offset=0):
        i = self.pos + offset
        return self.toks[i] if i < len(self.toks) else None

    def is_word(self, word, offset=0):
        t = self.peek(offset)
        return t is not None and t.kind == "word" and t.text.upper() == word

    def is_punct(self, text, offset=0):
        t = self.peek(offset)
        return t is not None and t.kind == "punct" and t.text == text

    def parse(self):
        if not self.toks:
            raise Unevaluable("empty predicate")
        node = self.or_expr()
        if self.pos != len(self.toks):
            raise Unevaluable(
                f"unexpected token {self.peek().text!r} in predicate")
        return node

    def or_expr(self):
        left = self.and_expr()
        while self.is_word("OR"):
            self.pos += 1
            left = ("or", left, self.and_expr())
        return left

    def and_expr(self):
        left = self.not_expr()
        while self.is_word("AND"):
            self.pos += 1
            left = ("and", left, self.not_expr())
        return left

    def not_expr(self):
        if self.is_word("NOT"):
            self.pos += 1
            return ("not", self.not_expr())
        return self.primary()

    def primary(self):
        tok = self.peek()
        if tok is None:
            raise Unevaluable("predicate ends unexpectedly")
        if self.is_punct("("):
            self.pos += 1
            node = self.or_expr()
            if not self.is_punct(")"):
                raise Unevaluable("missing closing parenthesis")
            self.pos += 1
            return node
        if self.is_word("TRUE"):
            self.pos += 1
            return ("const", True)
        if self.is_word("FALSE"):
            self.pos += 1
            return ("const", False)
        return self.comparison()

    def comparison(self):
        tok = self.peek()
        is_column = tok.kind == "ident" or (
            tok.kind == "word" and tok.text.upper() not in _PREDICATE_KEYWORDS)
        if not is_column:
            raise Unevaluable(f"cannot evaluate {tok.text!r}")
        field = self.columns.get(tok.text.lower())
        if field is None:
            raise Unevaluable(f"unknown column {tok.text!r}")
        _require_string_column(field)
        column = field["name"]
        self.pos += 1
        tok = self.peek()
        if tok is None:
            raise Unevaluable(f"dangling column reference {column!r}")
        if tok.kind in ("op", "punct") and tok.text in ("=", "<>", "!="):
            self.pos += 1
            return ("cmp", column, tok.text != "=", self.value())
        negate = False
        if self.is_word("NOT"):
            negate = True
            self.pos += 1
        if self.is_word("IN"):
            self.pos += 1
            if not self.is_punct("("):
                raise Unevaluable("IN expects a parenthesized list")
            self.pos += 1
            literals = []
            while True:
                t = self.peek()
                if t is None:
                    raise Unevaluable("IN list is not closed")
                if t.kind != "string":
                    raise Unevaluable(
                        f"IN list supports string literals only, got {t.text!r}")
                literals.append(t.text)
                self.pos += 1
                if self.is_punct(","):
                    self.pos += 1
                    continue
                if self.is_punct(")"):
                    self.pos += 1
                    break
                raise Unevaluable("IN list is not closed")
            return ("in", column, negate, frozenset(literals))
        raise Unevaluable(f"unsupported operator {tok.text!r}")

    def value(self):
        tok = self.peek()
        if tok is None:
            raise Unevaluable("comparison has no right-hand side")
        if tok.kind == "string":
            self.pos += 1
            return ("lit", tok.text)
        if self.is_word("SESSION_USER") and self.is_punct("(", 1) \
                and self.is_punct(")", 2):
            self.pos += 3
            return ("session_user",)
        raise Unevaluable(f"unsupported right-hand side {tok.text!r}")


def _require_string_column(field):
    """Only a scalar STRING column can be compared with a string literal.

    BigQuery does not coerce a string literal to INT64, BOOL, NUMERIC,
    DATE, or TIMESTAMP, and arrays have no equality, so a predicate over
    any other column is unevaluable here rather than a guessed count. A
    field without a declared type is unevaluable for the same reason.
    """
    name = field.get("name")
    type_name = _normalize_type(field.get("type"))
    if not type_name:
        raise Unevaluable(f"column {name} has no declared type")
    if (field.get("mode") or "NULLABLE").upper() == "REPEATED":
        raise Unevaluable(
            f"column {name} is ARRAY<{type_name}>; arrays have no equality")
    if type_name != "STRING":
        raise Unevaluable(
            f"column {name} is {type_name}; the emulator compares STRING "
            "columns with string literals only")


def _as_text(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _eval_node(node, row, session_user):
    kind = node[0]
    if kind == "const":
        return node[1]
    if kind == "not":
        v = _eval_node(node[1], row, session_user)
        return None if v is None else (not v)
    if kind == "and":
        a = _eval_node(node[1], row, session_user)
        b = _eval_node(node[2], row, session_user)
        if a is False or b is False:
            return False
        if a is None or b is None:
            return None
        return True
    if kind == "or":
        a = _eval_node(node[1], row, session_user)
        b = _eval_node(node[2], row, session_user)
        if a is True or b is True:
            return True
        if a is None or b is None:
            return None
        return False
    if kind == "cmp":
        value = row.get(node[1])
        if value is None:
            return None
        rhs = session_user if node[3][0] == "session_user" else node[3][1]
        if rhs is None:
            return None
        equal = _as_text(value) == rhs
        return (not equal) if node[2] else equal
    if kind == "in":
        value = row.get(node[1])
        if value is None:
            return None
        hit = _as_text(value) in node[3]
        return (not hit) if node[2] else hit
    raise Unevaluable(f"unknown node {kind}")


def compile_predicate(predicate, fields):
    """Return f(row, session_user) -> True, False, or None (SQL NULL)."""
    try:
        tokens = tokenize_sql(predicate or "")
    except SqlSyntaxError as exc:
        raise Unevaluable(str(exc))
    columns = {f["name"].lower(): f for f in fields}
    tree = _PredicateParser(tokens, columns).parse()

    def run(row, session_user):
        return _eval_node(tree, row, session_user)
    return run


def evaluate_predicate(predicate, rows, fields, session_user):
    """Count the rows for which the predicate is true.

    Supports TRUE, FALSE, col = 'lit', col <> 'lit', col != 'lit',
    col IN ('a', 'b'), col NOT IN (...), col = SESSION_USER(), AND, OR,
    NOT, and parentheses, where col is a scalar STRING column of fields
    (each field needs name and type; mode defaults to NULLABLE). NULL
    comparisons follow SQL three-valued logic. Anything else raises
    Unevaluable.
    """
    fn = compile_predicate(predicate, fields)
    return sum(1 for row in rows if fn(row, session_user) is True)


# --------------------------------------------------------- shared helpers

def _check_member(member):
    """Reject anything that is not a typed IAM principal, and every
    spelling of the two everyone-principals: bare, behind a type prefix
    (specialGroup:allAuthenticatedUsers is how bq grants a dataset to
    every Google account), or in another case."""
    if not isinstance(member, str) or not member:
        raise BackendError("member must be a non-empty principal string")
    kind, sep, value = member.partition(":")
    forbidden = {m.lower() for m in FORBIDDEN_MEMBERS}
    if member.lower() in forbidden or value.lower() in forbidden:
        raise BackendError(
            f"refusing to bind {member}: db-drift never widens access to "
            "every user")
    if not sep or not value or not _MEMBER_KIND_RE.match(kind):
        raise BackendError(
            f"member {member!r} must be typed, for example group:x@example.com")
    if _MEMBER_BAD_CHARS_RE.search(value):
        raise BackendError(
            f"member {member!r} contains whitespace, a quote, a backslash, "
            "or a control character")
    if kind == "specialGroup" and value not in PROJECT_SPECIAL_GROUPS:
        raise BackendError(
            f"member {member!r}: specialGroup accepts only "
            + ", ".join(PROJECT_SPECIAL_GROUPS))


def _parse_taxonomy_name(name, project, location):
    """(project, location, id) from a full taxonomy resource name that
    belongs to this backend. A policy tag name, a bare id, or a name in
    another project or location is refused so a delete never lands on
    the wrong resource. Data Catalog reports the project by number in
    some names, so a purely numeric project segment is accepted."""
    text = str(name or "")
    if "/policyTags/" in text:
        raise BackendError(
            f"{text} names a policy tag, not a taxonomy")
    m = TAXONOMY_NAME_RE.match(text)
    if not m:
        raise BackendError(
            f"expected a full taxonomy resource name projects/P/locations/"
            f"L/taxonomies/ID, got {text!r}")
    proj, loc, tax_id = m.groups()
    if loc.lower() != str(location).lower():
        raise BackendError(
            f"taxonomy {text} is in location {loc}, not {location}")
    if proj != project and not proj.isdigit():
        raise BackendError(
            f"taxonomy {text} is in project {proj}, not {project}")
    return proj, loc, tax_id


def _principal_email(principal):
    return principal.split(":", 1)[1] if ":" in principal else principal


def _normalize_type(type_name):
    up = (type_name or "").upper()
    return TYPE_ALIASES.get(up, up)


def _deep_copy(value):
    return json.loads(json.dumps(value))


def _table_ref(project, dataset, table):
    return f"`{project}.{dataset}.{table}`"


def _split_view_ref(text):
    dataset, _, table = str(text).partition(".")
    if not dataset or not table:
        raise BackendError(
            f"authorized view must be written dataset.view, got {text!r}")
    return dataset, table


def _canonical_entry(entry):
    """The comparable form of a dataset access entry."""
    if not isinstance(entry, dict):
        raise BackendError("dataset access entry must be a mapping")
    if "view" in entry:
        dataset, table = _split_view_ref(entry["view"])
        return {"view": f"{dataset}.{table}"}
    role = entry.get("role")
    member = entry.get("member")
    if not role or not member:
        raise BackendError(
            "dataset access entry needs role and member, or view")
    _check_member(member)
    return {"role": LEGACY_ROLES.get(role, role), "member": member}


def _access_key(canon):
    """What makes two canonical dataset access entries the same entry.

    bq stores user: and serviceAccount: members alike as userByEmail and
    reports a service account back as whichever prefix the reader
    guesses, so both prefixes compare equal here and emails compare
    without case.
    """
    if "view" in canon:
        return ("view", canon["view"])
    kind, _, value = canon["member"].partition(":")
    if kind in ("user", "serviceAccount"):
        kind = "userByEmail"
    return (canon["role"], kind, value.lower())


# ---------------------------------------------------------------- Backend

class Backend:
    """Protocol every backend implements. Methods raise NotImplementedError
    here so a missing override is loud."""

    mode = None

    def create_dataset(self, dataset):
        raise NotImplementedError

    def list_datasets(self):
        raise NotImplementedError

    def delete_dataset(self, dataset):
        raise NotImplementedError

    def run_ddl(self, sql):
        raise NotImplementedError

    def list_tables(self, dataset):
        raise NotImplementedError

    def get_table_schema(self, dataset, table):
        raise NotImplementedError

    def update_table_schema(self, dataset, table, fields):
        raise NotImplementedError

    def get_dataset_access(self, dataset):
        raise NotImplementedError

    def add_dataset_access(self, dataset, entry):
        raise NotImplementedError

    def get_table_bindings(self, dataset, table):
        raise NotImplementedError

    def add_table_binding(self, dataset, table, role, member):
        raise NotImplementedError

    def get_project_bindings(self):
        raise NotImplementedError

    def add_project_binding(self, role, member):
        raise NotImplementedError

    def create_taxonomy(self, display_name, activated):
        raise NotImplementedError

    def describe_taxonomy(self, name):
        raise NotImplementedError

    def list_taxonomies(self):
        raise NotImplementedError

    def delete_taxonomy(self, name):
        raise NotImplementedError

    def create_policy_tag(self, taxonomy, display_name, description=""):
        raise NotImplementedError

    def list_policy_tags(self, taxonomy):
        raise NotImplementedError

    def get_policy_tag_bindings(self, tag):
        raise NotImplementedError

    def add_policy_tag_binding(self, tag, role, member):
        raise NotImplementedError

    def create_row_policy(self, dataset, table, name, members, filter_sql):
        raise NotImplementedError

    def list_row_policies(self, dataset, table):
        raise NotImplementedError

    def load_ndjson(self, dataset, table, path, fields):
        raise NotImplementedError

    def count_rows(self, dataset, table):
        raise NotImplementedError

    def query_json(self, sql):
        raise NotImplementedError

    def query_fingerprint(self, dataset, table, spec):
        raise NotImplementedError

    def probe(self, principal, probe_sa, dataset, table, columns):
        raise NotImplementedError


# ------------------------------------------------------------- DDL parser

class _Ddl:
    """Cursor over one statement's tokens."""

    def __init__(self, sql, tokens):
        self.sql = sql
        self.toks = tokens
        self.pos = 0

    def peek(self, offset=0):
        i = self.pos + offset
        return self.toks[i] if i < len(self.toks) else None

    def word(self, offset=0):
        t = self.peek(offset)
        return t.text.upper() if t is not None and t.kind == "word" else None

    def is_punct(self, text, offset=0):
        t = self.peek(offset)
        return t is not None and t.kind == "punct" and t.text == text

    def take_words(self, *words):
        for i, w in enumerate(words):
            if self.word(i) != w:
                return False
        self.pos += len(words)
        return True

    def expect_word(self, word):
        if not self.take_words(word):
            raise BackendError(
                f"expected {word} at: {self.rest()[:80]!r}")

    def rest(self):
        t = self.peek()
        return self.sql[t.start:] if t is not None else ""

    def paren_group(self):
        """Return (open_idx, close_idx) of the group at the cursor and
        move past it."""
        if not self.is_punct("("):
            raise BackendError(f"expected '(' at: {self.rest()[:80]!r}")
        open_idx = self.pos
        try:
            close_idx = _match_paren(self.toks, open_idx)
        except SqlSyntaxError as exc:
            raise BackendError(str(exc))
        self.pos = close_idx + 1
        return open_idx, close_idx

    def read_name(self):
        """Read a possibly dotted, possibly backticked object name."""
        parts = []
        while True:
            t = self.peek()
            if t is None or t.kind not in ("word", "ident"):
                break
            if t.kind == "ident":
                parts.extend(t.text.split("."))
            else:
                parts.append(t.text)
            self.pos += 1
            if self.is_punct("."):
                self.pos += 1
                continue
            break
        if not parts:
            raise BackendError(
                f"expected an object name at: {self.rest()[:80]!r}")
        return parts

    def skip_by_clause(self, stop_words):
        """Skip 'X BY ...' up to the next top-level stop word."""
        self.pos += 2
        while self.peek() is not None:
            if self.is_punct("("):
                self.paren_group()
                continue
            if self.word() in stop_words:
                break
            self.pos += 1


def _split_top_level(tokens):
    """Split tokens on commas outside parentheses and angle brackets."""
    groups, current, depth = [], [], 0
    for t in tokens:
        if t.kind == "punct" and t.text in "(<":
            depth += 1
        elif t.kind == "punct" and t.text in ")>":
            depth -= 1
        if t.kind == "punct" and t.text == "," and depth == 0:
            groups.append(current)
            current = []
        else:
            current.append(t)
    if current:
        groups.append(current)
    return groups


def _parse_column(group):
    """One column definition to a bq field dict, or None for constraints."""
    first = group[0]
    if first.kind == "word" and first.text.upper() in (
            "PRIMARY", "FOREIGN", "CONSTRAINT"):
        return None
    if first.kind not in ("word", "ident"):
        raise BackendError(f"bad column definition near {first.text!r}")
    name = first.text
    if not IDENT_RE.match(name):
        raise BackendError(
            f"column name {name!r} must match [A-Za-z0-9_]+")
    cur = _Ddl("", group)
    cur.pos = 1
    type_tok = cur.peek()
    if type_tok is None or type_tok.kind != "word":
        raise BackendError(f"column {name} has no type")
    type_name = type_tok.text.upper()
    cur.pos += 1
    mode = "NULLABLE"
    if type_name == "ARRAY":
        if not cur.is_punct("<"):
            raise BackendError(f"column {name}: ARRAY needs <element type>")
        cur.pos += 1
        inner = cur.peek()
        if inner is None or inner.kind != "word":
            raise BackendError(f"column {name}: ARRAY needs an element type")
        type_name = inner.text.upper()
        cur.pos += 1
        if type_name in ("STRUCT", "ARRAY"):
            raise BackendError(
                f"column {name}: ARRAY<{type_name}> is not supported by the "
                "emulated backend")
        if cur.is_punct("("):
            cur.paren_group()
        if not cur.is_punct(">"):
            raise BackendError(f"column {name}: ARRAY type is not closed")
        cur.pos += 1
        mode = "REPEATED"
    if type_name == "STRUCT":
        raise BackendError(
            f"column {name}: STRUCT columns are not supported by the "
            "emulated backend")
    type_name = _normalize_type(type_name)
    if type_name not in KNOWN_TYPES:
        raise BackendError(f"column {name}: unknown type {type_name}")
    if cur.is_punct("("):
        cur.paren_group()
    while cur.peek() is not None:
        w = cur.word()
        if w == "NOT" and cur.word(1) == "NULL":
            if mode == "REPEATED":
                raise BackendError(
                    f"column {name}: ARRAY columns cannot be NOT NULL")
            mode = "REQUIRED"
            cur.pos += 2
        elif w == "OPTIONS" and cur.is_punct("(", 1):
            cur.pos += 1
            cur.paren_group()
        elif w == "COLLATE":
            cur.pos += 2
        elif w == "DEFAULT":
            cur.pos += 1
            while cur.peek() is not None and cur.word() not in (
                    "NOT", "OPTIONS", "COLLATE"):
                if cur.is_punct("("):
                    cur.paren_group()
                else:
                    cur.pos += 1
        else:
            raise BackendError(
                f"column {name}: unsupported modifier {cur.peek().text!r}")
    return {"name": name, "type": type_name, "mode": mode}


# ------------------------------------------------------- EmulatedBackend

class EmulatedBackend(Backend):
    """A JSON model of one BigQuery project on local disk.

    State lives in root/state.json; loaded rows live under
    root/data/<dataset>/<table>.ndjson.gz. Every write goes through
    save(), so a test can tamper with the JSON and reopen the backend.
    """

    mode = "emulated"

    def __init__(self, root, project, location, log=None):
        self.root = Path(root)
        self.project = project
        self.location = location
        self.log = log or OperationLog(None)
        self.state = self._load()

    # ---- persistence

    def _empty_state(self):
        return {"version": 1, "project": self.project,
                "location": self.location, "next_id": 1, "datasets": {},
                "project_bindings": [], "taxonomies": {}}

    def _load(self):
        path = self.root / STATE_FILE
        if not path.exists():
            return self._empty_state()
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise BackendError(f"emulator state at {path} is not JSON: {exc}")
        if not isinstance(state, dict):
            raise BackendError(
                f"emulator state at {path} is not a JSON object")
        for key in ("project", "location"):
            stored = state.get(key)
            wanted = getattr(self, key)
            if stored is not None and stored != wanted:
                raise BackendError(
                    f"emulator state at {path} belongs to {key} {stored!r}, "
                    f"not {wanted!r}; run bq-backend reset --yes to start "
                    "over or restore the migration's bigquery config")
        base = self._empty_state()
        for key, value in base.items():
            state.setdefault(key, value)
        return state

    def save(self):
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / STATE_FILE
        path.write_text(json.dumps(self.state, indent=2) + "\n",
                        encoding="utf-8")

    def _data_path(self, dataset, table):
        return self.root / "data" / dataset / f"{table}.ndjson.gz"

    def _remove_data(self, dataset, table):
        path = self._data_path(dataset, table)
        if path.exists():
            path.unlink()

    def _read_rows(self, dataset, table):
        path = self._data_path(dataset, table)
        if not path.exists():
            return []
        rows = []
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return rows

    # ---- lookups

    def _dataset(self, dataset):
        ds = self.state["datasets"].get(dataset)
        if ds is None:
            raise BackendError(
                f"dataset {dataset} not found in project {self.project}")
        return ds

    def _table(self, dataset, table):
        tbl = self._dataset(dataset)["tables"].get(table)
        if tbl is None:
            raise BackendError(f"table {dataset}.{table} not found")
        return tbl

    def _resolve(self, parts):
        """(project, dataset, table) from a parsed object name. Dataset
        and table must be plain identifiers: the table name becomes a
        file name under root/data, so a path in backticks is refused."""
        if len(parts) == 3:
            if parts[0] != self.project:
                raise BackendError(
                    f"statement names project {parts[0]!r} but the emulated "
                    f"backend project is {self.project!r}")
            project, dataset, table = parts
        elif len(parts) == 2:
            project, (dataset, table) = self.project, parts
        else:
            raise BackendError(
                "expected dataset.table or project.dataset.table, got "
                f"{'.'.join(parts)!r}")
        for label, value in (("dataset", dataset), ("table", table)):
            if not IDENT_RE.match(value or ""):
                raise BackendError(
                    f"{label} name {value!r} must match [A-Za-z0-9_]+")
        return project, dataset, table

    def _taxonomy(self, name):
        tax = self.state["taxonomies"].get(name)
        if tax is None:
            for candidate in self.state["taxonomies"].values():
                if candidate["name"].split("/")[-1] == str(name).split("/")[-1]:
                    return candidate
            raise BackendError(f"taxonomy {name} not found")
        return tax

    def _tag(self, tag):
        tax_name = str(tag).split("/policyTags/")[0]
        tax = self.state["taxonomies"].get(tax_name)
        if tax is None or tag not in tax["policyTags"]:
            raise BackendError(f"policy tag {tag} not found")
        return tax["policyTags"][tag]

    def _tag_exists(self, tag):
        try:
            self._tag(tag)
        except BackendError:
            return False
        return True

    def _next_id(self):
        n = self.state["next_id"]
        self.state["next_id"] = n + 1
        return n

    # ---- datasets

    def create_dataset(self, dataset):
        if not IDENT_RE.match(dataset or ""):
            raise BackendError(f"dataset name {dataset!r} must match "
                               "[A-Za-z0-9_]+")
        if dataset in self.state["datasets"]:
            raise BackendError(f"dataset {dataset} already exists")
        self.state["datasets"][dataset] = {"access": [], "tables": {}}
        self.save()
        self.log.record("create_dataset", dataset=dataset,
                        location=self.location)

    def list_datasets(self):
        return sorted(self.state["datasets"])

    def delete_dataset(self, dataset):
        self._dataset(dataset)
        del self.state["datasets"][dataset]
        data_dir = self.root / "data" / dataset
        if data_dir.exists():
            shutil.rmtree(data_dir)
        self.save()
        self.log.record("delete_dataset", dataset=dataset)

    # ---- DDL

    def run_ddl(self, sql):
        try:
            statements = split_statements(sql)
        except SqlSyntaxError as exc:
            raise BackendError(f"cannot tokenize DDL: {exc}")
        applied = []
        for text, tokens in statements:
            try:
                applied.append(self._apply_statement(text, tokens))
            except BackendError as exc:
                # Earlier statements are already saved; leave the trace.
                self.log.record("run_ddl", statements=applied,
                                failed=text[:200], error=str(exc), sql=sql)
                raise
            self.save()
        self.log.record("run_ddl", statements=applied, sql=sql)

    def _apply_statement(self, text, tokens):
        p = _Ddl(text, tokens)
        if p.word() == "CREATE":
            p.pos += 1
            or_replace = p.take_words("OR", "REPLACE")
            if p.take_words("TABLE"):
                return self._ddl_create_table(p, or_replace)
            if p.take_words("MATERIALIZED", "VIEW"):
                return self._ddl_create_view(p, or_replace, "MATERIALIZED_VIEW")
            if p.take_words("VIEW"):
                return self._ddl_create_view(p, or_replace, "VIEW")
            if p.take_words("ROW", "ACCESS", "POLICY"):
                return self._ddl_create_row_policy(p, or_replace)
        raise BackendError(
            "the emulated backend only runs CREATE TABLE, CREATE VIEW, "
            "CREATE MATERIALIZED VIEW, and CREATE ROW ACCESS POLICY; got: "
            f"{text[:80]}")

    def _ddl_create_table(self, p, or_replace):
        if_not_exists = p.take_words("IF", "NOT", "EXISTS")
        _, dataset, table = self._resolve(p.read_name())
        ds = self._dataset(dataset)
        open_idx, close_idx = p.paren_group()
        fields = []
        for group in _split_top_level(p.toks[open_idx + 1:close_idx]):
            if not group:
                continue
            field = _parse_column(group)
            if field is not None:
                fields.append(field)
        if not fields:
            raise BackendError(f"CREATE TABLE {dataset}.{table} has no columns")
        names = [f["name"].lower() for f in fields]
        if len(set(names)) != len(names):
            raise BackendError(
                f"CREATE TABLE {dataset}.{table} repeats a column name")
        while p.peek() is not None:
            w = p.word()
            if w in ("CLUSTER", "PARTITION") and p.word(1) == "BY":
                p.skip_by_clause(("OPTIONS", "CLUSTER", "PARTITION", "DEFAULT"))
            elif w == "OPTIONS" and p.is_punct("(", 1):
                p.pos += 1
                p.paren_group()
            elif w == "DEFAULT" and p.word(1) == "COLLATE":
                p.pos += 3
            else:
                raise BackendError(
                    f"unsupported clause in CREATE TABLE {dataset}.{table}: "
                    f"{p.rest()[:80]!r}")
        existing = ds["tables"].get(table)
        if existing is not None:
            if if_not_exists:
                return {"kind": "TABLE", "name": f"{dataset}.{table}",
                        "action": "exists"}
            if not or_replace:
                raise BackendError(f"table {dataset}.{table} already exists")
            self._remove_data(dataset, table)
        ds["tables"][table] = {"type": "TABLE", "fields": fields,
                               "bindings": [], "row_policies": {}}
        return {"kind": "TABLE", "name": f"{dataset}.{table}",
                "action": "replaced" if existing else "created"}

    def _ddl_create_view(self, p, or_replace, kind):
        if_not_exists = p.take_words("IF", "NOT", "EXISTS")
        _, dataset, table = self._resolve(p.read_name())
        ds = self._dataset(dataset)
        if p.is_punct("("):
            p.paren_group()
        while p.peek() is not None and p.word() != "AS":
            w = p.word()
            if w == "OPTIONS" and p.is_punct("(", 1):
                p.pos += 1
                p.paren_group()
            elif w in ("CLUSTER", "PARTITION") and p.word(1) == "BY":
                p.skip_by_clause(("OPTIONS", "CLUSTER", "PARTITION", "AS"))
            else:
                raise BackendError(
                    f"unsupported clause in CREATE {kind} {dataset}.{table}: "
                    f"{p.rest()[:80]!r}")
        p.expect_word("AS")
        if p.peek() is None:
            raise BackendError(f"view {dataset}.{table} has no body")
        body = p.sql[p.peek().start:p.toks[-1].end].strip()
        existing = ds["tables"].get(table)
        if existing is not None:
            if if_not_exists:
                return {"kind": kind, "name": f"{dataset}.{table}",
                        "action": "exists"}
            if not or_replace:
                raise BackendError(f"{dataset}.{table} already exists")
            if existing["type"] == "TABLE":
                raise BackendError(
                    f"{dataset}.{table} already exists as a TABLE")
        ds["tables"][table] = {
            "type": kind, "body": body,
            "bindings": existing["bindings"] if existing else [],
            "row_policies": {}}
        return {"kind": kind, "name": f"{dataset}.{table}",
                "action": "replaced" if existing else "created"}

    def _ddl_create_row_policy(self, p, or_replace):
        if_not_exists = p.take_words("IF", "NOT", "EXISTS")
        tok = p.peek()
        if tok is None or tok.kind not in ("word", "ident"):
            raise BackendError("CREATE ROW ACCESS POLICY needs a policy name")
        name = tok.text
        p.pos += 1
        p.expect_word("ON")
        _, dataset, table = self._resolve(p.read_name())
        tbl = self._table(dataset, table)
        p.expect_word("GRANT")
        p.expect_word("TO")
        open_idx, close_idx = p.paren_group()
        members = []
        for t in p.toks[open_idx + 1:close_idx]:
            if t.kind == "string":
                members.append(t.text)
            elif t.kind == "punct" and t.text == ",":
                continue
            else:
                raise BackendError(
                    f"GRANT TO expects quoted principals, got {t.text!r}")
        p.expect_word("FILTER")
        p.expect_word("USING")
        open_idx, close_idx = p.paren_group()
        filter_sql = p.sql[p.toks[open_idx].end:p.toks[close_idx].start].strip()
        if p.peek() is not None:
            raise BackendError(
                f"unexpected text after FILTER USING: {p.rest()[:80]!r}")
        action = self._put_row_policy(tbl, dataset, table, name, members,
                                      filter_sql, or_replace, if_not_exists)
        return {"kind": "ROW_ACCESS_POLICY", "name": f"{dataset}.{table}/{name}",
                "action": action}

    def _put_row_policy(self, tbl, dataset, table, name, members, filter_sql,
                        or_replace, if_not_exists):
        if not IDENT_RE.match(name or ""):
            raise BackendError(
                f"row access policy name {name!r} must match [A-Za-z0-9_]+")
        if tbl["type"] != "TABLE":
            raise BackendError(
                f"{dataset}.{table} is a {tbl['type']}; row access policies "
                "apply to tables only")
        if not members:
            raise BackendError(f"row access policy {name} names no principal")
        for m in members:
            _check_member(m)
        if not filter_sql:
            raise BackendError(f"row access policy {name} has an empty filter")
        if name in tbl["row_policies"]:
            if if_not_exists:
                return "exists"
            if not or_replace:
                raise BackendError(
                    f"row access policy {name} on {dataset}.{table} "
                    "already exists")
            action = "replaced"
        else:
            action = "created"
        tbl["row_policies"][name] = {"members": list(members),
                                     "filter": filter_sql}
        return action

    # ---- tables

    def list_tables(self, dataset):
        tables = self._dataset(dataset)["tables"]
        return [{"name": name, "type": tables[name]["type"]}
                for name in sorted(tables)]

    def get_table_schema(self, dataset, table):
        tbl = self._table(dataset, table)
        if tbl["type"] != "TABLE":
            raise BackendError(
                f"{dataset}.{table} is a {tbl['type']} and has no stored "
                "schema in the emulator")
        return _deep_copy(tbl["fields"])

    def update_table_schema(self, dataset, table, fields):
        tbl = self._table(dataset, table)
        if tbl["type"] != "TABLE":
            raise BackendError(f"{dataset}.{table} is a {tbl['type']}")
        old = {f["name"]: f for f in tbl["fields"]}
        new_names = [f.get("name") for f in fields]
        for name in old:
            if name not in new_names:
                raise BackendError(
                    f"schema update would drop column {name} from "
                    f"{dataset}.{table}; BigQuery does not allow that")
        stored = []
        for f in fields:
            name = f.get("name")
            if not name or not f.get("type"):
                raise BackendError("every field needs a name and a type")
            type_name = _normalize_type(f["type"])
            mode = (f.get("mode") or "NULLABLE").upper()
            prior = old.get(name)
            if prior is not None:
                if type_name != _normalize_type(prior["type"]):
                    raise BackendError(
                        f"column {name}: type change {prior['type']} to "
                        f"{f['type']} is not allowed")
                if mode == "REQUIRED" and prior["mode"] != "REQUIRED":
                    raise BackendError(
                        f"column {name}: mode cannot change to REQUIRED")
                if (prior["mode"] == "REPEATED") != (mode == "REPEATED"):
                    raise BackendError(
                        f"column {name}: mode cannot change between REPEATED "
                        "and scalar")
            elif mode == "REQUIRED":
                raise BackendError(
                    f"column {name}: a new column cannot be REQUIRED")
            entry = {"name": name, "type": type_name, "mode": mode}
            tags = (f.get("policyTags") or {}).get("names") or []
            for tag in tags:
                if not self._tag_exists(tag):
                    raise BackendError(
                        f"column {name}: policy tag {tag} does not exist")
            if tags:
                entry["policyTags"] = {"names": list(tags)}
            stored.append(entry)
        tbl["fields"] = stored
        self.save()
        self.log.record("update_table_schema", dataset=dataset, table=table,
                        tagged=[f["name"] for f in stored if "policyTags" in f])

    # ---- dataset access

    def get_dataset_access(self, dataset):
        return _deep_copy(self._dataset(dataset)["access"])

    def add_dataset_access(self, dataset, entry):
        ds = self._dataset(dataset)
        canon = _canonical_entry(entry)
        if "view" in canon:
            vds, vtable = _split_view_ref(canon["view"])
            vtbl = self.state["datasets"].get(vds, {}).get("tables", {}).get(
                vtable)
            if vtbl is None:
                raise BackendError(
                    f"authorized view {vds}.{vtable} does not exist")
            if vtbl["type"] not in ("VIEW", "MATERIALIZED_VIEW"):
                raise BackendError(
                    f"authorized view {vds}.{vtable} is a {vtbl['type']}")
        if _access_key(canon) in {_access_key(e) for e in ds["access"]}:
            return
        ds["access"].append(canon)
        self.save()
        self.log.record("add_dataset_access", dataset=dataset, entry=canon)

    # ---- table bindings

    def get_table_bindings(self, dataset, table):
        return _deep_copy(self._table(dataset, table)["bindings"])

    def add_table_binding(self, dataset, table, role, member):
        _check_member(member)
        tbl = self._table(dataset, table)
        binding = {"role": role, "member": member}
        if binding in tbl["bindings"]:
            return
        tbl["bindings"].append(binding)
        self.save()
        self.log.record("add_table_binding", dataset=dataset, table=table,
                        role=role, member=member)

    # ---- project bindings

    def get_project_bindings(self):
        return _deep_copy(self.state["project_bindings"])

    def add_project_binding(self, role, member):
        _check_member(member)
        binding = {"role": role, "member": member}
        if binding in self.state["project_bindings"]:
            return
        self.state["project_bindings"].append(binding)
        self.save()
        self.log.record("add_project_binding", role=role, member=member)

    # ---- taxonomies and policy tags

    def create_taxonomy(self, display_name, activated):
        for tax in self.state["taxonomies"].values():
            if tax["displayName"] == display_name:
                raise BackendError(
                    f"taxonomy {display_name!r} already exists in "
                    f"{self.project}/{self.location}")
        name = (f"projects/{self.project}/locations/{self.location}/"
                f"taxonomies/{self._next_id()}")
        self.state["taxonomies"][name] = {
            "name": name, "displayName": display_name,
            "activatedPolicyTypes": list(activated or []), "policyTags": {}}
        self.save()
        self.log.record("create_taxonomy", name=name, displayName=display_name,
                        activatedPolicyTypes=list(activated or []))
        return name

    def describe_taxonomy(self, name):
        tax = self._taxonomy(name)
        return {"name": tax["name"], "displayName": tax["displayName"],
                "activatedPolicyTypes": list(tax["activatedPolicyTypes"])}

    def list_taxonomies(self):
        return [self.describe_taxonomy(name)
                for name in self.state["taxonomies"]]

    def delete_taxonomy(self, name):
        _parse_taxonomy_name(name, self.project, self.location)
        if name not in self.state["taxonomies"]:
            raise BackendError(f"taxonomy {name} not found")
        del self.state["taxonomies"][name]
        self.save()
        self.log.record("delete_taxonomy", name=name)

    def create_policy_tag(self, taxonomy, display_name, description=""):
        tax = self._taxonomy(taxonomy)
        for tag in tax["policyTags"].values():
            if tag["displayName"] == display_name:
                raise BackendError(
                    f"policy tag {display_name!r} already exists in "
                    f"{tax['name']}")
        name = f"{tax['name']}/policyTags/{self._next_id()}"
        tax["policyTags"][name] = {"name": name, "displayName": display_name,
                                   "description": description or "",
                                   "bindings": []}
        self.save()
        self.log.record("create_policy_tag", name=name,
                        displayName=display_name)
        return name

    def list_policy_tags(self, taxonomy):
        tax = self._taxonomy(taxonomy)
        return [{"name": t["name"], "displayName": t["displayName"],
                 "description": t.get("description", "")}
                for t in tax["policyTags"].values()]

    def get_policy_tag_bindings(self, tag):
        return _deep_copy(self._tag(tag)["bindings"])

    def add_policy_tag_binding(self, tag, role, member):
        _check_member(member)
        entry = self._tag(tag)
        binding = {"role": role, "member": member}
        if binding in entry["bindings"]:
            return
        entry["bindings"].append(binding)
        self.save()
        self.log.record("add_policy_tag_binding", tag=tag, role=role,
                        member=member)

    # ---- row access policies

    def create_row_policy(self, dataset, table, name, members, filter_sql):
        tbl = self._table(dataset, table)
        action = self._put_row_policy(tbl, dataset, table, name, list(members),
                                      filter_sql, True, False)
        self.save()
        self.log.record("create_row_policy", dataset=dataset, table=table,
                        name=name, members=list(members), filter=filter_sql,
                        action=action)

    def list_row_policies(self, dataset, table):
        tbl = self._table(dataset, table)
        return [{"name": name, "members": list(p["members"]),
                 "filter": p["filter"]}
                for name, p in tbl.get("row_policies", {}).items()]

    # ---- data

    def load_ndjson(self, dataset, table, path, fields):
        tbl = self._table(dataset, table)
        if tbl["type"] != "TABLE":
            raise BackendError(f"{dataset}.{table} is a {tbl['type']}")
        table_fields = {f["name"]: f for f in tbl["fields"]}
        load_fields = {}
        for f in fields:
            name = f.get("name")
            if name not in table_fields:
                raise BackendError(
                    f"load schema names column {name!r} which is not in "
                    f"{dataset}.{table}")
            load_fields[name] = f
        rows = list(self._iter_ndjson(path))
        for idx, row in enumerate(rows, 1):
            if not isinstance(row, dict):
                raise BackendError(f"row {idx}: not a JSON object")
            for key in row:
                if key not in load_fields:
                    raise BackendError(
                        f"row {idx}: column {key!r} is not in the load schema")
            for name, f in table_fields.items():
                value = row.get(name)
                mode = f.get("mode", "NULLABLE")
                if mode == "REQUIRED" and value is None:
                    raise BackendError(
                        f"row {idx}: column {name} is REQUIRED but null "
                        "or missing")
                if mode == "REPEATED" and value is not None \
                        and not isinstance(value, list):
                    raise BackendError(
                        f"row {idx}: column {name} is REPEATED but the value "
                        "is not a list")
        target = self._data_path(dataset, table)
        target.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(target, "at", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        total = self.count_rows(dataset, table)
        self.log.record("load_ndjson", dataset=dataset, table=table,
                        source=str(path), rows_in_file=len(rows), rows=total)
        return total

    @staticmethod
    def _iter_ndjson(path):
        p = Path(path)
        if not p.exists():
            raise BackendError(f"NDJSON file not found: {p}")
        with open(p, "rb") as fh:
            magic = fh.read(2)
        opener = gzip.open if magic == b"\x1f\x8b" else open
        with opener(p, "rt", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError as exc:
                    raise BackendError(f"bad NDJSON line in {p}: {exc}")

    def count_rows(self, dataset, table):
        self._table(dataset, table)
        path = self._data_path(dataset, table)
        if not path.exists():
            return 0
        n = 0
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    n += 1
        return n

    def query_json(self, sql):
        raise BackendError(
            "the emulated backend has no SQL engine; use query_fingerprint "
            "or probe")

    def query_fingerprint(self, dataset, table, spec):
        bq_validate = importlib.import_module("db_drift.bq_validate")
        self._table(dataset, table)
        rows = self._read_rows(dataset, table)
        return bq_validate.fingerprint_from_rows(rows, spec)

    # ---- probes

    def _can_read(self, principal, dataset, table):
        tbl = self._table(dataset, table)
        for b in tbl["bindings"]:
            if b["member"] == principal and b["role"] in DATA_READ_ROLES:
                return True
        for entry in self._dataset(dataset)["access"]:
            if entry.get("member") == principal \
                    and entry.get("role") in DATA_READ_ROLES:
                return True
        for b in self.state["project_bindings"]:
            if b["member"] == principal and b["role"] in DATA_READ_ROLES:
                return True
        return False

    def _has_fine_grained_reader(self, principal, tag):
        try:
            bindings = self._tag(tag)["bindings"]
        except BackendError:
            return False
        return any(b["member"] == principal and b["role"] == ROLE_FGR
                   for b in bindings)

    def probe(self, principal, probe_sa, dataset, table, columns):
        def result(status, row_count, reason):
            self.log.record("probe", principal=principal, dataset=dataset,
                            table=table, columns=list(columns),
                            status=status, row_count=row_count)
            return {"status": status, "row_count": row_count,
                    "reason": reason + " (emulated)"}

        try:
            tbl = self._table(dataset, table)
        except BackendError as exc:
            return result("error", None, str(exc))
        if tbl["type"] != "TABLE":
            return result("unevaluable", None,
                          f"{dataset}.{table} is a {tbl['type']}; the "
                          "emulator has no SQL engine to evaluate its body")
        # BigQuery resolves column names without regard to case.
        by_name = {f["name"].lower(): f for f in tbl["fields"]}
        requested = []
        for col in columns:
            if col == "*":
                requested.extend(by_name)
            elif col.lower() in by_name:
                requested.append(col.lower())
            else:
                return result("error", None,
                              f"unknown column {col!r} in {dataset}.{table}")
        if not self._can_read(principal, dataset, table):
            return result("denied", None,
                          f"{principal} has no data read role on "
                          f"{dataset}.{table} at table, dataset, or project "
                          "scope")
        # Nobody bypasses a policy tag, dataset owners and project admins
        # included: BigQuery always requires the fine-grained reader role.
        for col in requested:
            field = by_name[col]
            for tag in (field.get("policyTags") or {}).get("names", []):
                if self._has_fine_grained_reader(principal, tag):
                    continue
                return result("denied", None,
                              f"column {field['name']} carries policy tag "
                              f"{tag} and {principal} lacks {ROLE_FGR} on it")
        rows = self._read_rows(dataset, table)
        policies = tbl.get("row_policies", {})
        if not policies:
            return result("ok", len(rows),
                          f"{len(rows)} rows as {principal}; no row access "
                          "policy on the table")
        applicable = {name: p for name, p in policies.items()
                      if principal in p["members"]}
        if not applicable:
            return result("ok", 0,
                          f"{dataset}.{table} has row access policies and "
                          f"none names {principal}; BigQuery returns no rows")
        session_user = _principal_email(principal)
        matched = set()
        for name, policy in applicable.items():
            try:
                fn = compile_predicate(policy["filter"], tbl["fields"])
            except Unevaluable as exc:
                return result("unevaluable", None,
                              f"row access policy {name} has a predicate the "
                              f"emulator cannot evaluate ({exc}): "
                              f"{policy['filter']}")
            for idx, row in enumerate(rows):
                if fn(row, session_user) is True:
                    matched.add(idx)
        return result("ok", len(matched),
                      f"{len(matched)} rows as {principal} through "
                      f"{', '.join(sorted(applicable))}")


# ----------------------------------------------------------- LiveBackend

def redact_argv(argv):
    """Copy of argv with any OAuth token value replaced."""
    out = []
    redact_next = False
    for item in argv:
        if redact_next:
            out.append("<redacted>")
            redact_next = False
        elif item.startswith("--oauth_access_token="):
            out.append("--oauth_access_token=<redacted>")
        elif item == "--oauth_access_token":
            out.append(item)
            redact_next = True
        else:
            out.append(item)
    return out


def default_runner(argv, stdin=None):
    """Run bq or gcloud. On Windows these are .cmd shims, so the executable
    is resolved through shutil.which at call time."""
    exe = shutil.which(argv[0])
    if not exe:
        raise BackendError(
            f"{argv[0]} not found on PATH; install the Google Cloud SDK")
    proc = subprocess.run([exe] + list(argv[1:]), capture_output=True,
                          text=True, encoding="utf-8", input=stdin)
    return proc.returncode, proc.stdout, proc.stderr


def default_http(method, url, headers, body):
    """One JSON request; returns (status, response text). An HTTP error
    status is returned, not raised, so the caller can log and redact."""
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    for key, value in headers.items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        raise BackendError(f"{method} {url}: {exc.reason}")


def parse_json_output(text):
    """The first JSON document in CLI output, or None when there is none.

    bq sometimes prefixes JSON with progress lines such as 'Waiting on
    job', so the parse starts at the first bracket that yields a document.
    """
    if not text:
        return None
    decoder = json.JSONDecoder()
    tried = 0
    for i, ch in enumerate(text):
        if ch not in "[{":
            continue
        tried += 1
        try:
            value, _ = decoder.raw_decode(text[i:])
            return value
        except ValueError:
            if tried >= 20:
                return None
    return None


def _flatten_bindings(policy):
    out = []
    if not isinstance(policy, dict):
        return out
    for b in policy.get("bindings") or []:
        for member in b.get("members") or []:
            out.append({"role": b.get("role"), "member": member})
    return out


class LiveBackend(Backend):
    """bq and gcloud CLI backend, plus three Data Catalog REST calls.

    runner(argv, stdin) -> (returncode, stdout, stderr). The default runs
    subprocess with UTF-8. http(method, url, headers, body) -> (status,
    text) serves create_taxonomy, create_policy_tag, and delete_taxonomy,
    which gcloud cannot do; the default uses urllib with a token from
    gcloud auth print-access-token. work_dir holds the schema and access
    documents bq reads from files; make_backend puts it under the
    workspace. Every call, failed ones included, records its argv or URL
    (tokens redacted) in the OperationLog. Written from the CLI and API
    documentation and mock-tested; not live-tested in this repository.
    """

    mode = "live"

    def __init__(self, project, location, runner=None, log=None,
                 work_dir=None, http=None):
        self.project = project
        self.location = location
        self.runner = runner
        self.http = http
        self.log = log or OperationLog(None)
        self.work_dir = Path(work_dir) if work_dir else None
        self._file_seq = 0

    # ---- plumbing

    def _call(self, argv, stdin=None):
        runner = self.runner or default_runner
        return runner(list(argv), stdin)

    def _run(self, argv, stdin=None):
        rc, out, err = self._call(argv, stdin)
        if rc != 0:
            entry = {"argv": redact_argv(argv), "rc": rc,
                     "stderr": (err or "").strip()[:800],
                     "stdout": (out or "").strip()[:800]}
            if stdin:
                entry["stdin"] = stdin[:800]
            self.log.record("command_failed", **entry)
            verb = next((a for a in argv[1:] if not a.startswith("--")), "")
            raise BackendError(
                f"{argv[0]} {verb} failed ({rc}): {(err or out).strip()[:800]}")
        return out

    def _bq(self, *args):
        return ["bq", f"--project_id={self.project}", "--format=json"] + list(args)

    def _bq_plain(self, *args):
        return ["bq", f"--project_id={self.project}"] + list(args)

    def _query_argv(self):
        return self._bq("query", "--use_legacy_sql=false", "--nouse_cache")

    @property
    def _dc_location(self):
        """Data Catalog location ids are lower case (us, eu, us-central1)
        even where the matching BigQuery location is written US or EU."""
        return str(self.location).lower()

    def _taxonomies(self, *args):
        return ["gcloud", "data-catalog", "taxonomies"] + list(args) + [
            f"--location={self._dc_location}", f"--project={self.project}",
            "--format=json"]

    def _access_token(self):
        argv = ["gcloud", "auth", "print-access-token"]
        rc, out, err = self._call(argv)
        token = (out or "").strip().splitlines()[0].strip() \
            if (out or "").strip() else ""
        if rc != 0 or not token:
            self.log.record("command_failed", argv=argv, rc=rc,
                            stderr=(err or "").strip()[:800])
            raise BackendError(
                f"gcloud auth print-access-token failed ({rc}): "
                f"{(err or '').strip()[:300]}")
        return token

    def _api_url(self, path):
        return f"{DATACATALOG_API}/{path}"

    def _datacatalog(self, method, path, body=None):
        """One Data Catalog API call as the active gcloud account. The
        token travels in a header only; responses are scrubbed of it
        before they reach a log or an error."""
        url = self._api_url(path)
        token = self._access_token()
        headers = {"Authorization": f"Bearer {token}",
                   "Content-Type": "application/json; charset=utf-8",
                   "Accept": "application/json"}
        status, text = (self.http or default_http)(method, url, headers, body)
        text = (text or "").replace(token, "<redacted>")
        if not 200 <= int(status) < 300:
            self.log.record("request_failed", method=method, url=url,
                            body=body, status=status, response=text[:800])
            raise BackendError(f"{method} {url} failed ({status}): {text[:800]}")
        doc = parse_json_output(text)
        return doc if isinstance(doc, dict) else {}

    def _work_file(self, stem, payload):
        if self.work_dir is None:
            raise BackendError(
                "LiveBackend needs work_dir to write schema and dataset "
                "access documents for bq; make_backend sets "
                "<workspace>/artifacts/bq-work")
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._file_seq += 1
        path = self.work_dir / f"{stem}-{self._file_seq}.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return path

    def _ref(self, dataset, table=None):
        return f"{self.project}:{dataset}" + (f".{table}" if table else "")

    @staticmethod
    def _taxonomy_id(name):
        return str(name).split("/policyTags/")[0].rstrip("/").split("/")[-1]

    @staticmethod
    def _tag_id(tag):
        return str(tag).rstrip("/").split("/")[-1]

    # ---- datasets

    def create_dataset(self, dataset):
        argv = self._bq("mk", "--dataset", f"--location={self.location}",
                        self._ref(dataset))
        self._run(argv)
        self.log.record("create_dataset", dataset=dataset, argv=argv)

    def _ls(self, *args):
        return self._bq("ls", f"--max_results={BQ_LS_MAX_RESULTS}", *args)

    def list_datasets(self):
        items = parse_json_output(self._run(self._ls("--datasets")))
        out = []
        for item in items if isinstance(items, list) else []:
            ref = item.get("datasetReference") or {}
            name = ref.get("datasetId") or str(item.get("id", "")).split(
                ":")[-1]
            if name:
                out.append(name)
        return out

    def delete_dataset(self, dataset):
        argv = self._bq_plain("rm", "-r", "-f", "-d", self._ref(dataset))
        self._run(argv)
        self.log.record("delete_dataset", dataset=dataset, argv=argv)

    # ---- DDL and queries

    def run_ddl(self, sql):
        argv = self._query_argv()
        self._run(argv, stdin=sql)
        self.log.record("run_ddl", argv=argv, sql=sql)

    def query_json(self, sql):
        rows = parse_json_output(self._run(self._query_argv(), stdin=sql))
        return rows if isinstance(rows, list) else []

    def list_tables(self, dataset):
        items = parse_json_output(self._run(self._ls(self._ref(dataset))))
        out = []
        for item in items if isinstance(items, list) else []:
            ref = item.get("tableReference") or {}
            name = ref.get("tableId") or str(item.get("id", "")).split(
                ".")[-1]
            if name:
                out.append({"name": name, "type": item.get("type", "TABLE")})
        return out

    def get_table_schema(self, dataset, table):
        fields = parse_json_output(self._run(
            self._bq("show", "--schema", self._ref(dataset, table))))
        if not isinstance(fields, list):
            raise BackendError(
                f"bq show --schema returned no schema for {dataset}.{table}")
        return fields

    def update_table_schema(self, dataset, table, fields):
        path = self._work_file(f"schema-{dataset}.{table}", fields)
        argv = self._bq_plain("update", self._ref(dataset, table), str(path))
        self._run(argv)
        self.log.record("update_table_schema", dataset=dataset, table=table,
                        argv=argv, schema_file=str(path))

    # ---- dataset access

    def _show_dataset(self, dataset):
        doc = parse_json_output(self._run(self._bq("show", self._ref(dataset))))
        if not isinstance(doc, dict):
            raise BackendError(f"bq show returned no document for {dataset}")
        return doc

    @staticmethod
    def _canonical_access(entries):
        out = []
        for e in entries or []:
            if not isinstance(e, dict):
                continue
            if "view" in e:
                v = e["view"] or {}
                out.append({"view": f"{v.get('datasetId')}.{v.get('tableId')}"})
                continue
            role = e.get("role")
            role = LEGACY_ROLES.get(role, role)
            member = None
            if "groupByEmail" in e:
                member = "group:" + e["groupByEmail"]
            elif "userByEmail" in e:
                email = e["userByEmail"]
                prefix = "serviceAccount:" if email.endswith(
                    "gserviceaccount.com") else "user:"
                member = prefix + email
            elif "domain" in e:
                member = "domain:" + e["domain"]
            elif "specialGroup" in e:
                member = "specialGroup:" + e["specialGroup"]
            elif "iamMember" in e:
                member = e["iamMember"]
            if role and member:
                out.append({"role": role, "member": member})
            else:
                out.append({"raw": e})
        return out

    def _access_to_bq(self, canon):
        if "view" in canon:
            dataset, table = _split_view_ref(canon["view"])
            return {"view": {"projectId": self.project, "datasetId": dataset,
                             "tableId": table}}
        role, member = canon["role"], canon["member"]
        kind, _, value = member.partition(":")
        if kind == "group":
            return {"role": role, "groupByEmail": value}
        if kind in ("user", "serviceAccount"):
            return {"role": role, "userByEmail": value}
        if kind == "domain":
            return {"role": role, "domain": value}
        if kind == "specialGroup":
            return {"role": role, "specialGroup": value}
        return {"role": role, "iamMember": member}

    def get_dataset_access(self, dataset):
        return self._canonical_access(self._show_dataset(dataset).get("access"))

    def add_dataset_access(self, dataset, entry):
        canon = _canonical_entry(entry)
        doc = self._show_dataset(dataset)
        access = list(doc.get("access") or [])
        present = {_access_key(e) for e in self._canonical_access(access)
                   if "raw" not in e}
        if _access_key(canon) in present:
            return
        access.append(self._access_to_bq(canon))
        doc["access"] = access
        path = self._work_file(f"access-{dataset}", doc)
        argv = self._bq_plain("update", "--source", str(path),
                              self._ref(dataset))
        self._run(argv)
        self.log.record("add_dataset_access", dataset=dataset, entry=canon,
                        argv=argv)

    # ---- table IAM

    def get_table_bindings(self, dataset, table):
        policy = parse_json_output(self._run(
            self._bq("get-iam-policy", self._ref(dataset, table))))
        return _flatten_bindings(policy)

    def add_table_binding(self, dataset, table, role, member):
        _check_member(member)
        argv = self._bq_plain("add-iam-policy-binding", f"--member={member}",
                              f"--role={role}", self._ref(dataset, table))
        self._run(argv)
        self.log.record("add_table_binding", dataset=dataset, table=table,
                        role=role, member=member, argv=argv)

    # ---- project IAM

    def get_project_bindings(self):
        policy = parse_json_output(self._run(
            ["gcloud", "projects", "get-iam-policy", self.project,
             "--format=json"]))
        return _flatten_bindings(policy)

    def add_project_binding(self, role, member):
        _check_member(member)
        # --condition=None: gcloud otherwise prompts (and fails without a
        # terminal) once the policy holds any conditional binding.
        argv = ["gcloud", "projects", "add-iam-policy-binding", self.project,
                f"--member={member}", f"--role={role}", "--condition=None",
                "--format=json"]
        self._run(argv)
        self.log.record("add_project_binding", role=role, member=member,
                        argv=argv)

    # ---- taxonomies and policy tags

    def _taxonomy_name(self, taxonomy):
        """Full resource name of a taxonomy given its name, a policy tag
        under it, or a bare id."""
        text = str(taxonomy).split("/policyTags/")[0].rstrip("/")
        if text.startswith("projects/"):
            return text
        return (f"projects/{self.project}/locations/{self._dc_location}/"
                f"taxonomies/{text}")

    def create_taxonomy(self, display_name, activated):
        parent = f"projects/{self.project}/locations/{self._dc_location}"
        body = {"displayName": display_name}
        if activated:
            body["activatedPolicyTypes"] = list(activated)
        doc = self._datacatalog("POST", f"{parent}/taxonomies", body)
        if not doc.get("name"):
            raise BackendError("taxonomies.create returned no name")
        self.log.record("create_taxonomy", name=doc["name"],
                        displayName=display_name,
                        activatedPolicyTypes=list(activated or []),
                        request=f"POST {self._api_url(parent)}/taxonomies")
        return doc["name"]

    def describe_taxonomy(self, name):
        doc = parse_json_output(self._run(self._taxonomies(
            "describe", self._taxonomy_id(name))))
        if not isinstance(doc, dict):
            raise BackendError(f"taxonomy {name} could not be described")
        return {"name": doc.get("name", name),
                "displayName": doc.get("displayName", ""),
                "activatedPolicyTypes": list(doc.get("activatedPolicyTypes") or [])}

    def list_taxonomies(self):
        items = parse_json_output(self._run(self._taxonomies("list")))
        return [{"name": d.get("name"), "displayName": d.get("displayName", ""),
                 "activatedPolicyTypes": list(d.get("activatedPolicyTypes") or [])}
                for d in (items if isinstance(items, list) else [])
                if isinstance(d, dict)]

    def delete_taxonomy(self, name):
        _parse_taxonomy_name(name, self.project, self._dc_location)
        self._datacatalog("DELETE", name)
        self.log.record("delete_taxonomy", name=name,
                        request=f"DELETE {self._api_url(name)}")

    def create_policy_tag(self, taxonomy, display_name, description=""):
        parent = self._taxonomy_name(taxonomy)
        body = {"displayName": display_name}
        if description:
            body["description"] = description
        doc = self._datacatalog("POST", f"{parent}/policyTags", body)
        if not doc.get("name"):
            raise BackendError("policyTags.create returned no name")
        self.log.record("create_policy_tag", name=doc["name"],
                        displayName=display_name,
                        request=f"POST {self._api_url(parent)}/policyTags")
        return doc["name"]

    def list_policy_tags(self, taxonomy):
        items = parse_json_output(self._run(self._taxonomies(
            "policy-tags", "list",
            f"--taxonomy={self._taxonomy_id(taxonomy)}")))
        return [{"name": d.get("name"), "displayName": d.get("displayName", ""),
                 "description": d.get("description", "")}
                for d in (items if isinstance(items, list) else [])
                if isinstance(d, dict)]

    def get_policy_tag_bindings(self, tag):
        policy = parse_json_output(self._run(self._taxonomies(
            "policy-tags", "get-iam-policy", self._tag_id(tag),
            f"--taxonomy={self._taxonomy_id(tag)}")))
        return _flatten_bindings(policy)

    def add_policy_tag_binding(self, tag, role, member):
        _check_member(member)
        argv = self._taxonomies(
            "policy-tags", "add-iam-policy-binding", self._tag_id(tag),
            f"--taxonomy={self._taxonomy_id(tag)}", f"--member={member}",
            f"--role={role}")
        self._run(argv)
        self.log.record("add_policy_tag_binding", tag=tag, role=role,
                        member=member, argv=argv)

    # ---- row access policies

    def create_row_policy(self, dataset, table, name, members, filter_sql):
        if not IDENT_RE.match(name or ""):
            raise BackendError(
                f"row access policy name {name!r} must match [A-Za-z0-9_]+")
        if not members:
            raise BackendError(f"row access policy {name} names no principal")
        for m in members:
            _check_member(m)
        grantees = ", ".join(
            '"' + m.replace("\\", "\\\\").replace('"', '\\"') + '"'
            for m in members)
        sql = (f"CREATE OR REPLACE ROW ACCESS POLICY {name} ON "
               f"{_table_ref(self.project, dataset, table)} GRANT TO "
               f"({grantees}) FILTER USING ({filter_sql})")
        argv = self._query_argv()
        self._run(argv, stdin=sql)
        self.log.record("create_row_policy", dataset=dataset, table=table,
                        name=name, members=list(members), filter=filter_sql,
                        argv=argv, sql=sql)

    def list_row_policies(self, dataset, table):
        items = parse_json_output(self._run(self._ls(
            "--row_access_policies", self._ref(dataset, table))))
        out = []
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            ref = item.get("rowAccessPolicyReference") or {}
            out.append({"name": ref.get("policyId") or item.get("name", ""),
                        "members": list(item.get("grantees") or []),
                        "filter": item.get("filterPredicate", "")})
        return out

    # ---- data

    def load_ndjson(self, dataset, table, path, fields):
        schema_path = self._work_file(f"load-schema-{dataset}.{table}", fields)
        argv = self._bq_plain("load", "--source_format=NEWLINE_DELIMITED_JSON",
                              f"--schema={schema_path}",
                              self._ref(dataset, table), str(path))
        self._run(argv)
        total = self.count_rows(dataset, table)
        self.log.record("load_ndjson", dataset=dataset, table=table,
                        source=str(path), rows=total, argv=argv)
        return total

    def count_rows(self, dataset, table):
        sql = (f"SELECT COUNT(*) AS n FROM "
               f"{_table_ref(self.project, dataset, table)}")
        rows = self.query_json(sql)
        if not rows or not isinstance(rows[0], dict) or "n" not in rows[0]:
            raise BackendError(
                f"count query returned no rows for {dataset}.{table}")
        try:
            return int(rows[0]["n"])
        except (TypeError, ValueError):
            raise BackendError(
                f"count query returned {rows[0]['n']!r} for {dataset}.{table}")

    def query_fingerprint(self, dataset, table, spec):
        bq_validate = importlib.import_module("db_drift.bq_validate")
        sql = bq_validate.bq_fingerprint_sql(self.project, dataset, table, spec)
        rows = self.query_json(sql)
        if not rows:
            raise BackendError(
                f"fingerprint query returned no rows for {dataset}.{table}")
        return rows[0]

    # ---- probes

    def _probe_sql(self, dataset, table, columns):
        ref = _table_ref(self.project, dataset, table)
        if not columns:
            return f"SELECT COUNT(*) AS n FROM {ref}"
        rendered = []
        for col in columns:
            if col == "*":
                rendered.append("*")
            elif IDENT_RE.match(col):
                rendered.append(f"`{col}`")
            else:
                raise BackendError(f"probe column {col!r} is not an identifier")
        return f"SELECT COUNT(*) AS n FROM (SELECT {', '.join(rendered)} FROM {ref})"

    def probe(self, principal, probe_sa, dataset, table, columns):
        if not probe_sa:
            return {"status": "unevaluable", "row_count": None,
                    "reason": f"no probe service account for {principal}; a "
                              "live probe impersonates one, so nothing ran"}
        sql = self._probe_sql(dataset, table, columns)
        token_argv = ["gcloud", "auth", "print-access-token",
                      f"--impersonate-service-account={probe_sa}"]
        rc, out, err = self._call(token_argv)
        token = (out or "").strip().splitlines()[0].strip() if (out or "").strip() else ""
        if rc != 0 or not token:
            status, count = "error", None
            reason = (f"could not obtain a token for {probe_sa}: "
                      f"{(err or '').strip()[:300]}")
            self.log.record("probe", principal=principal, probe_sa=probe_sa,
                            dataset=dataset, table=table, columns=list(columns),
                            argv=token_argv, status=status)
            return {"status": status, "row_count": count, "reason": reason}
        argv = self._bq(f"--oauth_access_token={token}", "query",
                        "--use_legacy_sql=false")
        rc, out, err = self._call(argv, sql)

        def scrub(text):
            return (text or "").replace(token, "<redacted>")

        if rc != 0:
            text = scrub(err) + "\n" + scrub(out)
            low = text.lower()
            if "access denied" in low or "permission" in low:
                status, count = "denied", None
            else:
                status, count = "error", None
            reason = text.strip()[:300]
        else:
            rows = parse_json_output(scrub(out))
            try:
                count = int(rows[0]["n"])
                status = "ok"
                reason = f"{count} rows as {probe_sa}"
            except (TypeError, ValueError, KeyError, IndexError):
                status, count = "error", None
                reason = "probe query returned no count: " + scrub(out)[:300]
        self.log.record("probe", principal=principal, probe_sa=probe_sa,
                        dataset=dataset, table=table, columns=list(columns),
                        argv=redact_argv(argv), sql=sql, status=status,
                        row_count=count)
        return {"status": status, "row_count": count, "reason": reason}


# ---------------------------------------------------------------- factory

def check_migration_name(migration):
    """The name becomes a directory under the tool home, so anything that
    could climb out of it (.., a separator, an empty string) is refused."""
    if not MIGRATION_NAME_RE.match(migration or ""):
        raise BackendError(
            f"migration name {migration!r} must match [A-Za-z0-9_-]+")
    return migration


def emulated_root(migration):
    return pg.TOOLS_ROOT / "bq-emulated" / check_migration_name(migration)


def make_backend(bq_cfg, migration, workspace):
    mode = bq_cfg.get("mode", "emulated")
    log = OperationLog(Path(workspace) / "artifacts" / "bq-operations.log")
    project = bq_cfg.get("project") or config.BQ_DEFAULTS["project"]
    location = bq_cfg.get("location") or config.BQ_DEFAULTS["location"]
    if mode == "emulated":
        return EmulatedBackend(emulated_root(migration), project, location,
                               log=log)
    if mode == "live":
        return LiveBackend(project, location, log=log,
                           work_dir=Path(workspace) / "artifacts" / "bq-work")
    raise BackendError(
        f"unknown bigquery mode {mode!r}; expected emulated or live")


# -------------------------------------------------------------------- CLI

def status_document(backend):
    doc = {"mode": backend.mode, "project": backend.project,
           "location": backend.location}
    if backend.mode == "emulated":
        doc["root"] = str(backend.root)
    doc["datasets"] = []
    for dataset in backend.list_datasets():
        tables = []
        for t in backend.list_tables(dataset):
            entry = {"name": t["name"], "type": t["type"]}
            if t["type"] == "TABLE":
                if backend.mode == "emulated":
                    entry["rows"] = backend.count_rows(dataset, t["name"])
                entry["row_policies"] = backend.list_row_policies(
                    dataset, t["name"])
            else:
                entry["row_policies"] = []
            tables.append(entry)
        doc["datasets"].append({"name": dataset, "tables": tables})
    doc["taxonomies"] = []
    for tax in backend.list_taxonomies():
        item = dict(tax)
        item["policyTags"] = backend.list_policy_tags(tax["name"])
        doc["taxonomies"].append(item)
    return doc


def main(argv):
    parser = argparse.ArgumentParser(prog="dbdrift.py bq-backend")
    parser.add_argument("--root", default=".",
                        help="project root holding migrations/")
    parser.add_argument("--migration", default=None)
    sub = parser.add_subparsers(dest="verb", required=True)
    status_p = sub.add_parser(
        "status", help="list datasets, tables, row policies, and taxonomies "
                       "as JSON")
    reset_p = sub.add_parser(
        "reset", help="emulated only: delete the emulator directory")
    reset_p.add_argument("--yes", action="store_true",
                         help="confirm deletion of the emulator directory")
    # --root and --migration are accepted before or after the verb.
    for p in (status_p, reset_p):
        p.add_argument("--root", default=argparse.SUPPRESS,
                       help=argparse.SUPPRESS)
        p.add_argument("--migration", default=argparse.SUPPRESS,
                       help=argparse.SUPPRESS)
    args = parser.parse_args(argv[1:])
    if args.migration is None:
        parser.error("the following arguments are required: --migration")
    try:
        check_migration_name(args.migration)
    except BackendError as exc:
        print(f"BQ-BACKEND ERROR: {exc}", file=sys.stderr)
        return 1
    try:
        mig = config.load_migration(args.root, args.migration)
        bq_cfg = config.bigquery_config(mig, args.migration)
    except config.ConfigError as exc:
        print(f"BQ-BACKEND ERROR: {exc}", file=sys.stderr)
        return 1
    ws = config.workspace(args.root, args.migration)
    try:
        if args.verb == "status":
            backend = make_backend(bq_cfg, args.migration, ws)
            print(json.dumps(status_document(backend), indent=2))
            return 0
        if bq_cfg["mode"] != "emulated":
            print("BQ-BACKEND ERROR: reset applies to emulated mode only; "
                  "live resources are removed by the rollback playbook "
                  "after typed confirmation", file=sys.stderr)
            return 1
        root = emulated_root(args.migration)
        if not args.yes:
            print(f"refusing to delete {root} without --yes", file=sys.stderr)
            return 2
        # Belt and braces: never remove anything outside bq-emulated/.
        base = (pg.TOOLS_ROOT / "bq-emulated").resolve()
        if root.resolve().parent != base:
            print(f"BQ-BACKEND ERROR: refusing to delete {root}; it is not "
                  f"a child of {base}", file=sys.stderr)
            return 1
        if root.exists():
            shutil.rmtree(root)
            print(f"removed {root}")
        else:
            print(f"nothing to remove at {root}")
        return 0
    except BackendError as exc:
        print(f"BQ-BACKEND ERROR: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError) as exc:
        print(f"BQ-BACKEND ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(["bq-backend"] + sys.argv[1:]))
