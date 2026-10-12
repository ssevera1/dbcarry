"""PostgreSQL to BigQuery predicate and SQL body translator.

Rule-based rewriting over a real token stream, conservative by design.
Every construct the translator recognizes is rewritten in place; every
construct it does not recognize is passed through and the result is
marked "review" with a note that tells the reviewer what to look at.
translate() never raises on strange input: the fallback is the original
text with confidence "review".

Public surface:

    tokenize(sql) -> [(kind, text), ...]
        kinds: string, qident, number, word, op, ws, paren
    translate(expr, context=None) -> {"sql", "confidence", "notes"}
        context = {"tables": {"orders": "`proj.retail.orders`",
                              "public.orders": "`proj.retail.orders`"},
                   "columns": ["id", ...] or [{"name": "id"}, ...]}

    A column entry may carry its BigQuery type, either directly as
    {"name": "ordered_at", "bq_type": "TIMESTAMP"} or as an inventory
    column dict ({"name", "data_type", "udt_name", ...}, mapped through
    bq_types.map_type). With types present the translator checks that
    date, datetime, and timestamp comparisons and the / operator keep
    their meaning; without them those checks fall back to notes.

The same translator serves row-level security predicates (pg_get_expr
output) and view bodies (pg_get_viewdef output). Input is expected in
that deparsed form: fully parenthesized, literals carrying explicit
::type casts, keyword-named functions double quoted ("left"(x, 3)), and
ILIKE spelled as the ~~* operator. Hand-written SQL is accepted but may
need review where it departs from that shape.

A "review" result is a partial attempt, not the source text. Every
construct the translator recognizes is still rewritten (casts, identity
words, ILIKE, table names), and only the construct that triggered the
note is left in PostgreSQL form. A reviewer fixes the noted spot rather
than starting over.
"""
import re

from db_carry import bq_types

AUTO_FUNCTIONS = {
    "coalesce", "nullif", "lower", "upper", "length", "abs", "greatest",
    "least", "trim", "ltrim", "rtrim", "concat", "round", "floor", "ceil",
    "ceiling", "mod", "left", "right", "replace", "starts_with", "ends_with",
    "cast", "extract", "ifnull", "count", "sum", "min", "max", "avg",
}

# Functions whose PostgreSQL meaning has no BigQuery counterpart. The text
# explains what a reviewer should do instead.
REVIEW_FUNCTIONS = {
    "current_setting": (
        "BigQuery has no session variables, so current_setting() cannot be "
        "evaluated there. Carry the value through SESSION_USER() and a "
        "mapping table on the target, or drop the condition."),
    "set_config": "BigQuery has no session variables.",
    "pg_has_role": (
        "BigQuery has no role membership check inside SQL. Model the "
        "membership as a lookup table keyed by SESSION_USER()."),
    "has_table_privilege": "BigQuery cannot test privileges inside SQL.",
    "has_column_privilege": "BigQuery cannot test privileges inside SQL.",
    "current_schema": "BigQuery has no schema search path.",
    "current_database": "BigQuery has no current database.",
    "inet_client_addr": "BigQuery does not expose the client address.",
}

# Allowlisted functions whose NULL handling differs. The BigQuery form is
# kept (the plan lists them as auto) and the difference is stated in a
# note so the plan output is honest about it.
NULL_SEMANTICS_NOTES = {
    "concat": (
        "concat(...) kept its arguments, but PostgreSQL concat skips NULL "
        "arguments while BigQuery CONCAT returns NULL when any argument is "
        "NULL; wrap nullable arguments in IFNULL(CAST(x AS STRING), '') if "
        "that matters."),
    "greatest": (
        "GREATEST(...) returns NULL in BigQuery when any argument is NULL, "
        "while PostgreSQL greatest ignores NULL arguments; write (SELECT "
        "MAX(v) FROM UNNEST([a, b]) v) to skip NULLs."),
    "least": (
        "LEAST(...) returns NULL in BigQuery when any argument is NULL, "
        "while PostgreSQL least ignores NULL arguments; write (SELECT "
        "MIN(v) FROM UNNEST([a, b]) v) to skip NULLs."),
}

# PostgreSQL names with an exact BigQuery counterpart under another name.
FUNCTION_RENAMES = {"btrim": "trim"}

# Functions whose argument list uses FROM as syntax, so a FROM inside
# their parentheses does not open a table list.
FROM_SYNTAX_FUNCTIONS = {"extract", "substring", "trim", "overlay",
                         "position"}

TIMESTAMP_FUNCTIONS = {"now", "transaction_timestamp", "statement_timestamp",
                       "clock_timestamp"}
IDENTITY_WORDS = {"current_user", "session_user", "current_role"}
SPECIAL_WORDS = {
    "current_timestamp": ("CURRENT_TIMESTAMP()", "TIMESTAMP"),
    "current_date": ("CURRENT_DATE()", "DATE"),
    "localtimestamp": ("CURRENT_DATETIME()", "DATETIME"),
    "current_time": ("CURRENT_TIME()", "TIME"),
    "localtime": ("CURRENT_TIME()", "TIME"),
}
TYPED_LITERAL_WORDS = {"date", "time", "timestamp", "timestamptz",
                       "interval"}

IDENTITY_NOTE = (
    "{word} became SESSION_USER(). PostgreSQL {word} is a role name and "
    "BigQuery SESSION_USER() is the caller's email address, so the compared "
    "column must hold Google identities on the target, or the predicate "
    "needs a mapping table from role names to email addresses.")

# Words that never name a function or a table, even when followed by "(".
KEYWORDS = {
    "all", "and", "any", "array", "as", "asc", "at", "between", "by", "case",
    "collate", "cross", "current", "date", "default", "delete", "desc",
    "distinct", "else", "end", "escape", "except", "exists", "false",
    "fetch", "filter", "first", "following", "for", "from", "full", "group",
    "having", "ilike", "in", "inner", "insert", "intersect", "interval",
    "into", "is", "isnull", "join", "last", "lateral", "left", "like",
    "limit", "local", "natural", "next", "not", "notnull", "null", "nulls",
    "offset", "on", "only", "or", "order", "outer", "over", "partition",
    "preceding", "range", "recursive", "returning", "right", "rows",
    "select", "set", "similar", "some", "symmetric", "table", "then",
    "time", "timestamp", "to", "true", "unbounded", "union", "unknown",
    "update", "using", "values", "when", "where", "window", "with",
    "within", "zone",
}

PASS_OPS = {"=", "<>", "!=", "<", ">", "<=", ">=", "+", "-", "*", "/", "||",
            ",", "."}
# (negated, case-insensitive)
LIKE_OPS = {"~~": (False, False), "!~~": (True, False),
            "~~*": (False, True), "!~~*": (True, True)}
REGEX_OPS = {"~", "~*", "!~", "!~*"}
OP_ADVICE = {
    "%": "BigQuery has no % operator; write MOD(a, b).",
    "^": "BigQuery has no ^ operator; write POW(a, b).",
    "->": "JSON access uses JSON_QUERY(x, '$.key') in BigQuery.",
    "->>": "JSON access uses JSON_VALUE(x, '$.key') in BigQuery.",
    "#>": "JSON path access uses JSON_QUERY(x, '$.a.b') in BigQuery.",
    "#>>": "JSON path access uses JSON_VALUE(x, '$.a.b') in BigQuery.",
    "@>": "array or JSON containment has no operator in BigQuery; use "
          "EXISTS over UNNEST or JSON functions.",
    "<@": "array or JSON containment has no operator in BigQuery; use "
          "EXISTS over UNNEST or JSON functions.",
    "&&": "array overlap has no operator in BigQuery; use EXISTS over "
          "UNNEST.",
    "?": "JSON key existence has no operator in BigQuery.",
    "?|": "JSON key existence has no operator in BigQuery.",
    "?&": "JSON key existence has no operator in BigQuery.",
    "@@": "full text search has no operator in BigQuery; use SEARCH().",
}

MULTI_CHAR_OPS = sorted(
    ["::", "!~~*", "!~~", "~~*", "~~", "!~*", "!~", "~*", "~", "<>", "!=",
     "<=", ">=", "||/", "||", "->>", "->", "#>>", "#>", "@>", "<@", "?|",
     "?&", "&&", "<<", ">>", "@@", "|/", "!!"],
    key=len, reverse=True)

WORD_RE = re.compile(r"[A-Za-z_\u0080-\uffff][A-Za-z0-9_$\u0080-\uffff]*")
NUMBER_RE = re.compile(
    r"\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?")
WS_RE = re.compile(r"\s+")
DOLLAR_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")

INTERVAL_RE = re.compile(
    r"^(\d+)\s+(second|minute|hour|day|week|month|year)s?$", re.I)
LITERAL_SHAPES = {
    "DATE": re.compile(r"^\d{4}-\d{1,2}-\d{1,2}$"),
    "TIME": re.compile(r"^\d{1,2}:\d{2}(:\d{2}(\.\d+)?)?$"),
    "DATETIME": re.compile(
        r"^\d{4}-\d{1,2}-\d{1,2}([ T]\d{1,2}:\d{2}(:\d{2}(\.\d+)?)?)?$"),
    "TIMESTAMP": re.compile(
        r"^\d{4}-\d{1,2}-\d{1,2}([ T]\d{1,2}:\d{2}(:\d{2}(\.\d+)?)?)?"
        r"(\s*(Z|UTC|[+-]\d{1,2}(:?\d{2})?))?$", re.I),
}

# String spellings PostgreSQL accepts for a boolean literal. BigQuery
# CAST(x AS BOOL) accepts only 'true' and 'false'.
BOOL_TRUE_WORDS = {"t", "true", "y", "yes", "on", "1"}
BOOL_FALSE_WORDS = {"f", "false", "n", "no", "off", "0"}

# A cast to a character type with an explicit length truncates in
# PostgreSQL; BigQuery STRING has no length.
CHAR_LENGTH_RE = re.compile(
    r"^(?:character\s+varying|varchar|character|char)\s*\(\s*\d+\s*\)", re.I)

# numeric(p, s) rounds to s decimals in PostgreSQL; BigQuery NUMERIC keeps
# nine, so the scale is applied with ROUND (both round half away from
# zero).
NUMERIC_SCALE_RE = re.compile(
    r"^(?:numeric|decimal)\s*\(\s*\d+\s*,\s*(\d+)\s*\)$", re.I)

# The hex form of a bytea literal as pg_get_expr prints it: '\x6575'.
HEX_BYTEA_RE = re.compile(r"^\\x((?:[0-9A-Fa-f]{2})*)$")

# Interval field lists that format_type appends: interval day to second.
INTERVAL_FIELDS = {"year", "month", "day", "hour", "minute", "second"}

SET_OPERATORS = {"union", "intersect", "except"}

COMPARE_OPS = {"=", "<>", "!=", "<", ">", "<=", ">="}
TEMPORAL_TYPES = {"DATE", "DATETIME", "TIMESTAMP"}
NON_INTEGER_TYPES = {"NUMERIC", "BIGNUMERIC", "FLOAT64"}
# PostgreSQL types behind each BigQuery temporal type, for the notes.
PG_TEMPORAL_NAMES = {
    "TIMESTAMP": "timestamp with time zone",
    "DATETIME": "timestamp without time zone",
    "DATE": "date",
}

DIVISION_NOTE = (
    "PostgreSQL / truncates when both operands are integers; BigQuery / "
    "returns FLOAT64. Use DIV(a, b) for integer operands, keep / for "
    "NUMERIC or FLOAT64.")

# EXTRACT fields. PASS fields mean the same in both engines (BigQuery's
# own part names are included so hand-written BigQuery input passes).
# RENAME fields have an exact BigQuery part under another name. REVIEW
# fields differ in numbering or have no EXTRACT part at all; the text is
# the BigQuery replacement to write by hand.
EXTRACT_PASS = {
    "year", "month", "day", "hour", "minute", "second", "quarter",
    "isoyear", "isoweek", "dayofweek", "dayofyear", "microsecond",
    "millisecond", "date", "time", "datetime",
}
EXTRACT_RENAME = {"week": "ISOWEEK"}
EXTRACT_REVIEW = {
    "epoch": "UNIX_SECONDS(ts) for a TIMESTAMP (UNIX_MICROS(ts) / 1e6 to "
             "keep the fraction) or UNIX_DATE(d) * 86400 for a DATE",
    "dow": "EXTRACT(DAYOFWEEK FROM x) - 1, because BigQuery DAYOFWEEK is "
           "1-based (1 is Sunday, 7 is Saturday) while PostgreSQL dow is "
           "0 (Sunday) to 6",
    "isodow": "MOD(EXTRACT(DAYOFWEEK FROM x) + 5, 7) + 1, because BigQuery "
              "has no ISO day number (PostgreSQL isodow is 1 Monday to 7 "
              "Sunday)",
    "doy": "EXTRACT(DAYOFYEAR FROM x)",
    "century": "no EXTRACT part; compute it from EXTRACT(YEAR FROM x)",
    "decade": "no EXTRACT part; DIV(EXTRACT(YEAR FROM x), 10)",
    "millennium": "no EXTRACT part; compute it from EXTRACT(YEAR FROM x)",
    "microseconds": "EXTRACT(MICROSECOND FROM x) returns only the "
                    "fraction, while PostgreSQL microseconds is the whole "
                    "seconds field times 1000000",
    "milliseconds": "EXTRACT(MILLISECOND FROM x) returns only the "
                    "fraction, while PostgreSQL milliseconds is the whole "
                    "seconds field times 1000",
    "timezone": "no EXTRACT part; BigQuery TIMESTAMP values carry no zone",
    "timezone_hour": "no EXTRACT part; BigQuery TIMESTAMP values carry no "
                     "zone",
    "timezone_minute": "no EXTRACT part; BigQuery TIMESTAMP values carry "
                       "no zone",
    "julian": "no EXTRACT part; UNIX_DATE(d) + 2440588",
}

# Words that end a FROM list when scanning backwards for the clause a
# word belongs to. FROM and JOIN themselves mean the word is a table.
CLAUSE_STOP_WORDS = {
    "select", "where", "group", "by", "having", "order", "limit", "offset",
    "window", "using", "union", "intersect", "except", "with", "set",
    "values", "returning", "into", "when", "then", "else", "case",
    "partition", "over", "on",
}


class TokenizeError(ValueError):
    pass


# ------------------------------------------------------------------ tokenizer

def _scan_quoted(sql, j, quote, backslash=False):
    """Return the index after the closing quote; j is just past the opener.

    A doubled quote inside the literal is an escape. With backslash=True
    (E'' strings) a backslash also escapes the next character.
    """
    n = len(sql)
    while j < n:
        ch = sql[j]
        if backslash and ch == "\\":
            j += 2
            continue
        if ch == quote:
            if j + 1 < n and sql[j + 1] == quote:
                j += 2
                continue
            return j + 1
        j += 1
    raise TokenizeError(f"unterminated {quote} quote")


def tokenize(sql):
    """Split SQL into (kind, text) tokens; joining the texts gives sql back.

    Kinds: string (including E'' and dollar quoted), qident (double quoted
    identifier), number, word, op (operators, commas, brackets, and any
    character the tokenizer has no rule for), ws (whitespace and
    comments), paren.
    """
    tokens = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        m = WS_RE.match(sql, i)
        if m:
            tokens.append(("ws", m.group()))
            i = m.end()
            continue
        if sql.startswith("--", i):
            end = sql.find("\n", i)
            end = n if end < 0 else end
            tokens.append(("ws", sql[i:end]))
            i = end
            continue
        if sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            if end < 0:
                raise TokenizeError("unterminated block comment")
            tokens.append(("ws", sql[i:end + 2]))
            i = end + 2
            continue
        if ch == "'":
            end = _scan_quoted(sql, i + 1, "'")
            tokens.append(("string", sql[i:end]))
            i = end
            continue
        if ch in "eE" and i + 1 < n and sql[i + 1] == "'":
            end = _scan_quoted(sql, i + 2, "'", backslash=True)
            tokens.append(("string", sql[i:end]))
            i = end
            continue
        if ch == '"':
            end = _scan_quoted(sql, i + 1, '"')
            tokens.append(("qident", sql[i:end]))
            i = end
            continue
        if ch == "$":
            m = DOLLAR_RE.match(sql, i)
            if m:
                tag = m.group()
                end = sql.find(tag, m.end())
                if end < 0:
                    raise TokenizeError("unterminated dollar quoted string")
                tokens.append(("string", sql[i:end + len(tag)]))
                i = end + len(tag)
                continue
        if ch.isdigit() or (ch == "." and i + 1 < n and sql[i + 1].isdigit()):
            m = NUMBER_RE.match(sql, i)
            tokens.append(("number", m.group()))
            i = m.end()
            continue
        m = WORD_RE.match(sql, i)
        if m:
            tokens.append(("word", m.group()))
            i = m.end()
            continue
        if ch in "()":
            tokens.append(("paren", ch))
            i += 1
            continue
        for op in MULTI_CHAR_OPS:
            if sql.startswith(op, i):
                tokens.append(("op", op))
                i += len(op)
                break
        else:
            tokens.append(("op", ch))
            i += 1
    return tokens


# ------------------------------------------------------------- output items

def _item(kind, text, **info):
    d = {"k": kind, "t": text}
    d.update(info)
    return d


def _join(items):
    return "".join(it["t"] for it in items)


def _prev_sig(out):
    j = len(out) - 1
    while j >= 0 and out[j]["k"] == "ws":
        j -= 1
    return j


def _prev_sig_word(out, back=1):
    """Lower-cased text of the back-th significant word item, or ""."""
    j = len(out)
    for _ in range(back):
        j -= 1
        while j >= 0 and out[j]["k"] == "ws":
            j -= 1
        if j < 0:
            return ""
    it = out[j]
    return it["t"].lower() if it["k"] == "word" else ""


def _skip_ws(tokens, i):
    while i < len(tokens) and tokens[i][0] == "ws":
        i += 1
    return i


def _match(tokens, i, opener, closer):
    """Index of the token closing the group opened at i, or None."""
    depth = 0
    for k in range(i, len(tokens)):
        kind, text = tokens[k]
        if kind in ("paren", "op"):
            if text == opener:
                depth += 1
            elif text == closer:
                depth -= 1
                if depth == 0:
                    return k
    return None


def _strip_ws_items(items):
    a, b = 0, len(items)
    while a < b and items[a]["k"] == "ws":
        a += 1
    while b > a and items[b - 1]["k"] == "ws":
        b -= 1
    return items[a:b]


def _is_group(items, opener="open", closer="close"):
    if len(items) < 2 or items[0]["k"] != opener or items[-1]["k"] != closer:
        return False
    depth = 0
    for idx, it in enumerate(items):
        if it["k"] == opener:
            depth += 1
        elif it["k"] == closer:
            depth -= 1
            if depth == 0 and idx != len(items) - 1:
                return False
    return depth == 0


def _single_item(items):
    """The one atom these items form, with parentheses stripped, or None.

    A single atom is a literal, a word, a quoted identifier, a dotted chain
    of those, a function call, or one of the translated atoms this module
    emits. Groups of operators are not single atoms.
    """
    items = _strip_ws_items(items)
    if not items:
        return None
    if len(items) == 1:
        it = items[0]
        if it["k"] in ("atom", "word", "number", "qident"):
            return it
        return None
    if _is_group(items):
        return _single_item(items[1:-1])
    if items[0].get("fn") and _is_group(items[1:]):
        return _item("atom", _join(items))
    if items[0]["k"] == "word" and items[0]["t"].lower() == "array" \
            and _is_group(items[1:], "obracket", "cbracket"):
        return _item("atom", _join(items))
    if _is_group(items, "obracket", "cbracket"):
        return _item("atom", _join(items))
    # dotted chain: a.b.c
    if len(items) % 2 == 1:
        ok = True
        for idx, it in enumerate(items):
            if idx % 2 == 0:
                if it["k"] not in ("word", "qident", "atom"):
                    ok = False
            elif not (it["k"] == "op" and it["t"] == "."):
                ok = False
        if ok:
            return _item("atom", _join(items))
    return None


def _collapse_parens(items):
    """Drop redundant outer parenthesis layers, keeping one around a group.

    pg_get_expr wraps a cast operand in its own parentheses even when the
    expression inside already has some, so ((a + b))::text arrives with
    two layers. One layer is kept because the operand is not a single
    atom and the parentheses may carry precedence.
    """
    items = _strip_ws_items(items)
    while _is_group(items):
        inner = _strip_ws_items(items[1:-1])
        if not _is_group(inner):
            break
        items = inner
    return items


def _is_word(it, *words):
    return it["k"] == "word" and it["t"].lower() in words


def _atom_start(out, j):
    """Index where the atom ending at out[j] starts, or None.

    An atom is a literal, a word or quoted identifier with its dotted
    qualifiers, a parenthesized or bracketed group with the function
    name or ARRAY word before it, or a CASE ... END expression (the
    deparser does not parenthesize CASE as an operator argument).
    """
    if j < 0:
        return None
    kind = out[j]["k"]
    if kind in ("close", "cbracket"):
        opener = "open" if kind == "close" else "obracket"
        depth = 0
        k = j
        while k >= 0:
            if out[k]["k"] == kind:
                depth += 1
            elif out[k]["k"] == opener:
                depth -= 1
                if depth == 0:
                    break
            k -= 1
        if k < 0:
            return None
        p = k - 1
        while p >= 0 and out[p]["k"] == "ws":
            p -= 1
        if p >= 0 and (out[p].get("fn") or (
                kind == "cbracket" and _is_word(out[p], "array"))):
            return p
        return k
    if _is_word(out[j], "end"):
        depth = 0
        for k in range(j, -1, -1):
            if _is_word(out[k], "end"):
                depth += 1
            elif _is_word(out[k], "case"):
                depth -= 1
                if depth == 0:
                    return k
        return None
    if kind in ("atom", "word", "number", "qident"):
        start = j
        while start >= 2 and out[start - 1]["k"] == "op" \
                and out[start - 1]["t"] == "." \
                and out[start - 2]["k"] in ("word", "qident"):
            start -= 2
        return start
    return None


def _atom_finish(out, k):
    """Index of the last item of the atom starting at out[k], or None."""
    n = len(out)
    if k >= n:
        return None
    it = out[k]
    kind = it["k"]
    if kind == "op" and it["t"] == "-" and k + 1 < n \
            and out[k + 1]["k"] == "number":
        return k + 1
    if kind in ("open", "obracket"):
        closer = "close" if kind == "open" else "cbracket"
        depth = 0
        for m in range(k, n):
            if out[m]["k"] == kind:
                depth += 1
            elif out[m]["k"] == closer:
                depth -= 1
                if depth == 0:
                    return m
        return None
    if _is_word(it, "case"):
        depth = 0
        for m in range(k, n):
            if _is_word(out[m], "case"):
                depth += 1
            elif _is_word(out[m], "end"):
                depth -= 1
                if depth == 0:
                    return m
        return None
    if kind not in ("atom", "word", "number", "qident"):
        return None
    end = k
    while end + 2 < n and out[end + 1]["k"] == "op" \
            and out[end + 1]["t"] == "." \
            and out[end + 2]["k"] in ("word", "qident", "atom"):
        end += 2
    m = end + 1
    while m < n and out[m]["k"] == "ws":
        m += 1
    if out[end].get("fn") and m < n and out[m]["k"] == "open":
        return _atom_finish(out, m)
    return end


def _pop_atom(out):
    """Remove and return the items forming the atom that ends out.

    Trailing whitespace is removed too. Returns None when out does not end
    with something atom-shaped (for example an operator).
    """
    j = _prev_sig(out)
    start = _atom_start(out, j)
    if start is None:
        return None
    items = out[start:j + 1]
    del out[start:]
    return items


def _is_column_ref(items):
    """True when items are a bare column reference (a, t.a, "A", t."A")."""
    items = _strip_ws_items(items)
    while _is_group(items):
        items = _strip_ws_items(items[1:-1])
    if not items or len(items) % 2 == 0:
        return False
    for idx, it in enumerate(items):
        if idx % 2:
            if not (it["k"] == "op" and it["t"] == "."):
                return False
        elif it["k"] not in ("word", "qident") or it.get("fn") \
                or (it["k"] == "word" and it["t"].lower() in KEYWORDS):
            return False
    return True


def _case_end(tokens, j):
    """Index after the END matching the CASE at tokens[j], or None."""
    depth = 0
    for k in range(j, len(tokens)):
        kind, text = tokens[k]
        if kind != "word":
            continue
        lower = text.lower()
        if lower == "case":
            depth += 1
        elif lower == "end":
            depth -= 1
            if depth == 0:
                return k + 1
    return None


def _bq_string(body):
    body = (body.replace("\\", "\\\\").replace("'", "\\'")
            .replace("\n", "\\n").replace("\r", "\\r"))
    return "'" + body + "'"


def _bq_ident(inner):
    inner = inner.replace("\\", "\\\\").replace("`", "\\`")
    return "`" + inner + "`"


def _column_bq_type(col):
    """BigQuery type family of a context column entry, or None.

    Accepts {"name", "bq_type"} and inventory column dicts (data_type,
    udt_name, ...). ARRAY<T> and other parameterized types are reduced
    to their outer name.
    """
    if not isinstance(col, dict):
        return None
    bq = col.get("bq_type") or col.get("type")
    if not bq and (col.get("data_type") or col.get("udt_name")):
        bq = bq_types.map_type(col)[0]
    if not bq:
        return None
    return str(bq).upper().split("<")[0].split("(")[0].strip() or None


def _unquote(token):
    """Source-side name of a word or qident token."""
    kind, text = token
    if kind == "qident":
        return text[1:-1].replace('""', '"')
    return text


# ------------------------------------------------------------- translator

class _Translator:
    def __init__(self, context):
        ctx = context or {}
        tables = ctx.get("tables") or {}
        self.tables = {}
        self.tables_lower = {}
        for key, value in tables.items():
            self.tables[str(key)] = str(value)
            self.tables_lower[str(key).lower()] = str(value)
        self.columns = set()
        # column name -> BigQuery type, or None when the name is declared
        # with two different types (an alias-qualified reference cannot
        # tell them apart, so the type counts as unknown).
        self.column_types = {}
        for col in ctx.get("columns") or []:
            name = col if isinstance(col, str) else (
                col.get("name") or col.get("column") or "")
            if not name:
                continue
            key = str(name).lower()
            self.columns.add(key)
            bq = _column_bq_type(col)
            if bq is None:
                continue
            if key in self.column_types and self.column_types[key] != bq:
                self.column_types[key] = None
            else:
                self.column_types[key] = bq
        self.notes = []
        self.review = False
        # Set by translate(): whether the whole expression has a FROM or
        # JOIN. Without one there is no table position to qualify.
        self.has_from = False
        # Set by translate(): names bound by WITH, never inventory tables.
        self.cte_names = set()

    def note(self, text, review=False):
        if review:
            self.review = True
        if text not in self.notes:
            self.notes.append(text)

    def qualify(self, name):
        if name in self.tables:
            return self.tables[name]
        return self.tables_lower.get(name.lower())

    # -- type names -----------------------------------------------------

    def _read_type(self, tokens, k):
        """Read a type name starting at k (after :: or AS).

        Returns (type_text, is_array, raw_text, next_index, fields).
        type_text is None when no type name is there. fields is the
        interval field list ("day to second") or "". A typmod may sit
        after the first word (timestamp(0) with time zone) or after the
        whole name (character varying(20)); it stays out of type_text and
        inside raw_text.
        """
        start = _skip_ws(tokens, k)
        k = start
        n = len(tokens)
        fields = ""
        if k >= n or tokens[k][0] not in ("word", "qident"):
            return None, False, "", k, fields
        words = []
        if tokens[k][0] == "qident":
            words.append(tokens[k][1][1:-1].replace('""', '"'))
            k += 1
        else:
            words.append(tokens[k][1])
            k += 1
            # schema qualified type name: keep the last part
            if k + 1 < n and tokens[k] == ("op", ".") \
                    and tokens[k + 1][0] == "word":
                words = [tokens[k + 1][1]]
                k += 2
            k = self._skip_typmod(tokens, k)
            while True:
                m = _skip_ws(tokens, k)
                if m >= n or tokens[m][0] != "word":
                    break
                candidate = " ".join(words + [tokens[m][1]]).lower()
                if any(mw == candidate or mw.startswith(candidate + " ")
                       for mw in bq_types.MULTI_WORD_TYPES):
                    words.append(tokens[m][1])
                    k = m + 1
                else:
                    break
        k = self._skip_typmod(tokens, k)
        if len(words) == 1 and words[0].lower() == "interval":
            parts = []
            m = _skip_ws(tokens, k)
            if m < n and tokens[m][0] == "word" \
                    and tokens[m][1].lower() in INTERVAL_FIELDS:
                parts.append(tokens[m][1].lower())
                k = m + 1
                m = _skip_ws(tokens, k)
                m2 = _skip_ws(tokens, m + 1)
                if m < n and tokens[m][0] == "word" \
                        and tokens[m][1].lower() == "to" \
                        and m2 < n and tokens[m2][0] == "word" \
                        and tokens[m2][1].lower() in INTERVAL_FIELDS:
                    parts.extend(["to", tokens[m2][1].lower()])
                    k = m2 + 1
                k = self._skip_typmod(tokens, k)
            fields = " ".join(parts)
        is_array = False
        m = _skip_ws(tokens, k)
        while m < n and tokens[m] == ("op", "["):
            close = _match(tokens, m, "[", "]")
            if close is None:
                break
            is_array = True
            k = close + 1
            m = _skip_ws(tokens, k)
        raw = "".join(t for _, t in tokens[start:k])
        return " ".join(words), is_array, raw, k, fields

    @staticmethod
    def _skip_typmod(tokens, k):
        """Index after a parenthesized typmod group at k (or k itself)."""
        m = _skip_ws(tokens, k)
        if m < len(tokens) and tokens[m] == ("paren", "("):
            close = _match(tokens, m, "(", ")")
            if close is not None:
                return close + 1
        return k

    def column_type(self, text):
        """BigQuery type of a column reference, or None when unknown."""
        name = text.strip("`").lower()
        return self.column_types.get(name)

    # -- atoms in the input stream ---------------------------------------

    def _atom_end(self, tokens, j):
        """Index just past the atom starting at j, including trailing casts."""
        n = len(tokens)
        if j >= n:
            return None
        kind, text = tokens[j]
        if kind == "paren" and text == "(":
            close = _match(tokens, j, "(", ")")
            if close is None:
                return None
            k = close + 1
        elif kind == "op" and text == "-" and j + 1 < n \
                and tokens[j + 1][0] == "number":
            k = j + 2
        elif kind == "word":
            lower = text.lower()
            k = j + 1
            m = _skip_ws(tokens, k)
            if lower == "case":
                k = _case_end(tokens, j)
                if k is None:
                    return None
            elif lower == "array" and m < n and tokens[m] == ("op", "["):
                close = _match(tokens, m, "[", "]")
                if close is None:
                    return None
                k = close + 1
            else:
                while k + 1 < n and tokens[k] == ("op", ".") \
                        and tokens[k + 1][0] in ("word", "qident"):
                    k += 2
                m = _skip_ws(tokens, k)
                if m < n and tokens[m] == ("paren", "(") \
                        and (lower not in KEYWORDS
                             or lower in AUTO_FUNCTIONS):
                    close = _match(tokens, m, "(", ")")
                    if close is None:
                        return None
                    k = close + 1
                elif m < n and tokens[m][0] == "string" \
                        and lower in TYPED_LITERAL_WORDS:
                    k = m + 1
        elif kind in ("string", "number", "qident"):
            k = j + 1
            while k + 1 < n and tokens[k] == ("op", ".") \
                    and tokens[k + 1][0] in ("word", "qident"):
                k += 2
            # a quoted function name: "left"(x, 3) as pg_get_expr writes it
            m = _skip_ws(tokens, k)
            if kind == "qident" and m < n and tokens[m] == ("paren", "("):
                close = _match(tokens, m, "(", ")")
                if close is None:
                    return None
                k = close + 1
        else:
            return None
        while True:
            m = _skip_ws(tokens, k)
            if m < n and tokens[m] == ("op", "::"):
                type_text, _, _, k2, _ = self._read_type(tokens, m + 1)
                if type_text is None:
                    return k
                k = k2
            else:
                return k

    # -- main pass ---------------------------------------------------------

    def run(self, tokens, base_depth=0):
        return _join(self._run_items(tokens, base_depth))

    def _run_items(self, tokens, base_depth=0):
        out = []
        frames = []
        n = len(tokens)
        i = 0
        while i < n:
            kind, text = tokens[i]
            if kind == "ws":
                out.append(_item("ws", text))
                i += 1
            elif kind == "paren":
                if text == "(":
                    j = _prev_sig(out)
                    name = None
                    if j >= 0 and out[j].get("fn"):
                        name = out[j]["t"].lower()
                    frames.append(name)
                    out.append(_item("open", "("))
                else:
                    if frames:
                        frames.pop()
                    else:
                        self.note("The expression has an unbalanced closing "
                                  "parenthesis.", review=True)
                    out.append(_item("close", ")"))
                i += 1
            elif kind == "string":
                out.append(self._string(text))
                i += 1
            elif kind == "qident":
                inner = text[1:-1].replace('""', '"')
                nxt = _skip_ws(tokens, i + 1)
                if nxt < n and tokens[nxt] == ("paren", "("):
                    # pg_get_expr double quotes keyword-named functions:
                    # "left"(x, 3), "substring"(x, 1, 2). Treat the quoted
                    # name exactly like a bare function name.
                    self._strip_pg_catalog(out)
                    if WORD_RE.fullmatch(inner):
                        i = self._function(out, i, inner, inner.lower())
                    else:
                        i = self._function(out, i, _bq_ident(inner),
                                           inner.lower(), kind="qident")
                else:
                    prev = _prev_sig(out)
                    after_dot = prev >= 0 and out[prev]["k"] == "op" \
                        and out[prev]["t"] == "."
                    plain = _item("qident", _bq_ident(inner))
                    if after_dot:
                        out.append(plain)
                        i += 1
                    else:
                        i = self._qualify_ref(out, tokens, i, inner, plain)
            elif kind == "number":
                out.append(_item("number", text))
                i += 1
            elif kind == "op":
                i = self._op(out, tokens, i, frames, base_depth)
            else:
                i = self._word(out, tokens, i, frames, base_depth)
        if frames and base_depth == 0:
            self.note("The expression has an unclosed parenthesis.",
                      review=True)
        self._check_operators(out)
        return out

    def _string(self, text):
        if text.startswith("$"):
            self.note(f"The dollar quoted string {text[:24]} has no BigQuery "
                      "form; rewrite it as a single quoted string.",
                      review=True)
            return _item("atom", text, bq="STRING")
        if text[0] in "eE":
            body = text[2:-1].replace("''", "\\'")
            self.note(f"The escape string {text[:24]} kept its backslash "
                      "escapes; BigQuery reads most of them the same way, "
                      "check the result.", review=True)
            return _item("atom", "'" + body + "'", bq="STRING")
        body = text[1:-1].replace("''", "'")
        return _item("atom", _bq_string(body), lit=body, bq="STRING")

    # -- operators -----------------------------------------------------------

    def _op(self, out, tokens, i, frames, base_depth):
        text = tokens[i][1]
        depth = base_depth + len(frames)
        if text == "::":
            return self._cast(out, tokens, i)
        if text in LIKE_OPS:
            negated, ci = LIKE_OPS[text]
            q = _skip_ws(tokens, i + 1)
            if q < len(tokens) and tokens[q][0] == "word" \
                    and tokens[q][1].lower() in ("any", "all", "some"):
                return self._like_quantified(out, tokens, q, negated, ci,
                                             depth, fallback=text)
            if not ci:
                out.append(_item("word", "NOT LIKE" if negated else "LIKE"))
                return i + 1
            return self._like(out, tokens, i + 1, negated, depth,
                              fallback=text)
        if text in REGEX_OPS:
            self.note(f"The regular expression operator {text} has no "
                      "BigQuery operator; rewrite it with REGEXP_CONTAINS() "
                      "and check the pattern, since BigQuery uses RE2 "
                      "syntax.", review=True)
            out.append(_item("op", text))
            return i + 1
        if text in PASS_OPS:
            out.append(_item("op", text))
            return i + 1
        if text == ";":
            if base_depth == 0 and not frames \
                    and _skip_ws(tokens, i + 1) >= len(tokens):
                return i + 1
            self.note("A semicolon inside the expression separates "
                      "statements; only one statement can be translated.",
                      review=True)
            out.append(_item("op", text))
            return i + 1
        if text == "[":
            j = _prev_sig(out)
            if j >= 0 and out[j]["k"] == "word" \
                    and out[j]["t"].lower() == "array":
                del out[j:]
                out.append(_item("obracket", "["))
            else:
                self.note("Array subscripts are 1-based in PostgreSQL; "
                          "BigQuery needs arr[ORDINAL(n)] for the same "
                          "element (or arr[OFFSET(n - 1)]).", review=True)
                out.append(_item("obracket", "["))
            return i + 1
        if text == "]":
            out.append(_item("cbracket", "]"))
            return i + 1
        advice = OP_ADVICE.get(text, "it has no automatic BigQuery "
                                     "translation.")
        self.note(f"The operator {text} needs a hand translation: {advice}",
                  review=True)
        out.append(_item("op", text))
        return i + 1

    def _cast(self, out, tokens, i):
        type_text, is_array, raw, k, fields = self._read_type(tokens, i + 1)
        atom = _pop_atom(out)
        if atom is None or type_text is None:
            self.note("A :: cast has no operand or no type name; translate "
                      "it by hand.", review=True)
            if atom:
                out.extend(atom)
            out.append(_item("op", "::"))
            return i + 1
        single = _single_item(atom)
        atom_text = single["t"] if single else _join(_collapse_parens(atom))
        pg = type_text.lower()
        original = f"{_join(atom)}::{raw}"
        if is_array:
            self.note(f"The cast to the array type {raw} needs a hand "
                      "translation (BigQuery arrays are ARRAY<T> and have "
                      "no cast from other types).", review=True)
            out.append(_item("atom", original))
            return k
        if pg == "interval":
            out.append(self._interval(single, original, fields))
            return k
        target = bq_types.cast_type_name(pg)
        if target is None:
            self.note(f"The cast to {raw} has no BigQuery type mapping; "
                      "pick the BigQuery type by hand.", review=True)
            out.append(_item("atom", original))
            return k
        if CHAR_LENGTH_RE.match(raw):
            self.note(f"The cast to {raw} truncates the value to that many "
                      "characters in PostgreSQL (and character(n) pads "
                      "it); BigQuery STRING has no length, so write "
                      "LEFT(x, n) (or RPAD(LEFT(x, n), n)) by hand if the "
                      "length matters.", review=True)
        scale = NUMERIC_SCALE_RE.match(raw)
        if scale:
            s = int(scale.group(1))
            if s <= 9:
                self.note(f"The cast to {raw} became ROUND(CAST(x AS "
                          f"NUMERIC), {s}): PostgreSQL rounds to the "
                          "declared scale (half away from zero, as BigQuery "
                          "ROUND does) and BigQuery NUMERIC keeps nine "
                          "decimal places.")
                inner = atom_text if single and single.get("bq") == target \
                    else f"CAST({atom_text} AS {target})"
                out.append(_item("atom", f"ROUND({inner}, {s})", bq=target))
                return k
            self.note(f"The cast to {raw} has a scale beyond NUMERIC's "
                      "nine decimal places; pick BIGNUMERIC and the "
                      "rounding by hand.", review=True)
        if target == "JSON":
            return self._json_cast(out, single, atom_text, raw, k)
        if target == "BYTES" and single and single.get("lit") is not None:
            lit = single["lit"]
            m = HEX_BYTEA_RE.match(lit)
            if m:
                out.append(_item("atom", f"FROM_HEX('{m.group(1)}')",
                                 bq=target))
                return k
            self.note(f"The bytea literal '{lit}' is not in hex form, so "
                      "its bytes cannot be decoded here; write a BigQuery "
                      "b'...' literal or FROM_HEX() by hand (CAST(x AS "
                      "BYTES) would keep the text's UTF-8 bytes).",
                      review=True)
        if single and single.get("lit") is not None and target == "BOOL":
            lit = single["lit"]
            spelled = lit.strip().lower()
            if spelled in BOOL_TRUE_WORDS:
                out.append(_item("atom", "TRUE", bq="BOOL"))
                return k
            if spelled in BOOL_FALSE_WORDS:
                out.append(_item("atom", "FALSE", bq="BOOL"))
                return k
            self.note(f"The literal '{lit}' is not a boolean spelling; "
                      "BigQuery CAST(x AS BOOL) accepts only 'true' and "
                      "'false', so pick TRUE or FALSE by hand.", review=True)
        if single and single.get("bq") == target:
            out.append(_item("atom", atom_text, bq=target,
                             lit=single.get("lit")))
            return k
        if single and single.get("lit") is not None \
                and target in LITERAL_SHAPES:
            lit = single["lit"]
            if not LITERAL_SHAPES[target].match(lit.strip()):
                self.note(f"The literal '{lit}' is not an ISO 8601 value; "
                          f"BigQuery {target} literals accept only that "
                          "form, not spellings like 'now', 'today', "
                          "'infinity', or day-first dates.", review=True)
            out.append(_item("atom", f"{target} {_bq_string(lit)}",
                             bq=target))
            return k
        out.append(_item("atom", f"CAST({atom_text} AS {target})",
                         bq=target))
        return k

    def _interval(self, single, original, fields=""):
        lit = single.get("lit") if single else None
        m = INTERVAL_RE.match(lit.strip()) if lit is not None else None
        if not m:
            shown = f"'{lit}'" if lit is not None else original
            self.note(f"The interval {shown} is not in the form "
                      "'N unit' that translates to INTERVAL N UNIT; write "
                      "the BigQuery interval by hand.", review=True)
            return _item("atom", original)
        unit = m.group(2).lower()
        if fields:
            # PostgreSQL drops the fields finer than the lowest one in
            # the list: '90 minutes'::interval hour is 1 hour, while
            # '1 day'::interval hour to minute keeps the day.
            order = ["year", "month", "week", "day", "hour", "minute",
                     "second"]
            lowest = fields.split()[-1]
            if order.index(unit) > order.index(lowest):
                self.note(f"The interval '{lit}' is restricted to the "
                          f"field list '{fields}', which truncates it to "
                          f"whole {lowest}s in PostgreSQL; BigQuery INTERVAL "
                          "has no field list, so write the truncated value "
                          "by hand.", review=True)
                return _item("atom", original)
        return _item("atom", f"INTERVAL {int(m.group(1))} {unit.upper()}",
                     bq="INTERVAL")

    def _json_cast(self, out, single, atom_text, raw, k):
        """Emit a cast to json or jsonb.

        BigQuery CAST(x AS JSON) follows TO_JSON, so a STRING becomes a
        JSON string value instead of being parsed. Text operands need
        PARSE_JSON; anything else is left to the reviewer.
        """
        bq = single.get("bq") if single else None
        if single and bq is None and single["k"] in ("word", "qident"):
            bq = self.column_type(single["t"])
        if bq == "JSON":
            out.append(_item("atom", atom_text, bq="JSON"))
            return k
        if bq == "STRING" or (single and single.get("lit") is not None):
            out.append(_item("atom", f"PARSE_JSON({atom_text})", bq="JSON"))
            return k
        self.note(f"The cast to {raw} needs a hand translation: BigQuery "
                  "CAST(x AS JSON) turns a STRING into a JSON string value "
                  "rather than parsing it, so write PARSE_JSON(x) for text "
                  "and TO_JSON(x) for structured values.", review=True)
        out.append(_item("atom", f"CAST({atom_text} AS JSON)", bq="JSON"))
        return k

    def _like(self, out, tokens, j, negated, depth, fallback):
        """Emit LOWER(lhs) [NOT] LIKE LOWER(rhs); j is after the operator."""
        j = _skip_ws(tokens, j)
        k = self._atom_end(tokens, j)
        # hand-written input: the pattern may be a || chain
        while k is not None:
            m = _skip_ws(tokens, k)
            if m < len(tokens) and tokens[m] == ("op", "||"):
                k = self._atom_end(tokens, _skip_ws(tokens, m + 1))
            else:
                break
        lhs = _pop_atom(out)
        while lhs is not None:
            p = _prev_sig(out)
            if p < 0 or out[p]["k"] != "op" or out[p]["t"] != "||":
                break
            q = p
            while q > 0 and out[q - 1]["k"] == "ws":
                q -= 1
            tail = out[q:]
            del out[q:]
            more = _pop_atom(out)
            if more is None:
                out.extend(tail)
                break
            lhs = more + tail + lhs
        if lhs is None or k is None:
            self.note("A case-insensitive LIKE has a missing operand; "
                      "translate it by hand.", review=True)
            if lhs:
                out.extend(lhs)
                out.append(_item("ws", " "))
            out.append(_item("op", fallback))
            return j
        single = _single_item(lhs)
        lhs_text = single["t"] if single else _join(_collapse_parens(lhs))
        rhs_text = self.run(tokens[j:k], base_depth=depth).strip()
        op = "NOT LIKE" if negated else "LIKE"
        out.append(_item("atom",
                         f"LOWER({lhs_text}) {op} LOWER({rhs_text})"))
        return k

    def _like_quantified(self, out, tokens, q, negated, ci, depth, fallback):
        """Emit lhs [NOT] LIKE ANY|ALL (p1, p2, ...); q is at ANY/ALL/SOME.

        pg_get_expr writes x ILIKE ANY (ARRAY[...]) as
        (x ~~* ANY (ARRAY['a%'::text, 'b%'::text])). BigQuery's quantified
        LIKE has the same ANY, SOME, ALL and NOT semantics as the
        PostgreSQL operator forms, so the quantifier is kept as is and
        only the pattern list changes shape. The rewrite runs only when the
        argument is an ARRAY literal of string literals; anything else
        (an array column, expressions) is left for review.
        """
        n = len(tokens)
        quant = tokens[q][1]
        open_idx = _skip_ws(tokens, q + 1)
        pattern = None
        if open_idx < n and tokens[open_idx] == ("paren", "("):
            pattern = self._array_arg(tokens, open_idx)
        lhs = _pop_atom(out)
        elems = None
        if pattern is not None:
            elems = self._string_elements(tokens[pattern[0]:pattern[1]],
                                          depth)
        if lhs is None or elems is None:
            self.note(f"{fallback} {quant} (...) over something other than "
                      "an ARRAY literal of string patterns needs a hand "
                      "translation: BigQuery has x [NOT] LIKE ANY|ALL "
                      "(p1, p2, ...) and x [NOT] LIKE ANY|ALL "
                      "UNNEST(array), and a case-insensitive match needs "
                      "LOWER() on x and on every pattern.", review=True)
            if lhs:
                out.extend(lhs)
                out.append(_item("ws", " "))
            out.append(_item("op", fallback))
            out.append(_item("ws", " "))
            out.append(_item("word", quant))
            return q + 1
        single = _single_item(lhs)
        lhs_text = single["t"] if single else _join(_collapse_parens(lhs))
        if ci:
            lhs_text = f"LOWER({lhs_text})"
            elems = [f"LOWER({e})" for e in elems]
        op = "NOT LIKE" if negated else "LIKE"
        out.append(_item("atom", f"{lhs_text} {op} {quant.upper()} "
                                 f"({', '.join(elems)})"))
        return pattern[2]

    def _array_arg(self, tokens, open_idx):
        """(elem_start, elem_end, after_close) for "(ARRAY[...])" at open_idx.

        Returns None when the parenthesized argument is not exactly one
        ARRAY literal.
        """
        n = len(tokens)
        j = _skip_ws(tokens, open_idx + 1)
        if j < n and tokens[j][0] == "word" and tokens[j][1].lower() == "array":
            j2 = _skip_ws(tokens, j + 1)
            if j2 < n and tokens[j2] == ("op", "["):
                close_b = _match(tokens, j2, "[", "]")
                if close_b is not None:
                    j3 = _skip_ws(tokens, close_b + 1)
                    if j3 < n and tokens[j3] == ("paren", ")"):
                        return (j2 + 1, close_b, j3 + 1)
        return None

    def _string_elements(self, tokens, depth):
        """Translated texts of a comma separated list of string literals.

        Returns None when any element is something other than a plain
        string literal (a cast to a string type is fine, that is how
        pg_get_expr writes them).
        """
        pieces, cur, level = [], [], 0
        for tok in tokens:
            kind, text = tok
            if kind == "paren" or (kind == "op" and text in ("[", "]")):
                level += 1 if text in ("(", "[") else -1
            if kind == "op" and text == "," and level == 0:
                pieces.append(cur)
                cur = []
            else:
                cur.append(tok)
        pieces.append(cur)
        result = []
        for piece in pieces:
            single = _single_item(self._run_items(piece, base_depth=depth))
            if single is None or single.get("lit") is None:
                return None
            result.append(single["t"])
        return result

    # -- words -------------------------------------------------------------------

    def _strip_pg_catalog(self, out):
        """Drop a "pg_catalog." prefix that ends out; True when it did."""
        prev = _prev_sig(out)
        if prev >= 1 and out[prev]["k"] == "op" and out[prev]["t"] == "." \
                and out[prev - 1]["k"] == "word" \
                and out[prev - 1]["t"].lower() == "pg_catalog":
            del out[prev - 1:]
            return True
        return False

    def _function(self, out, i, text, lower, kind="word"):
        """Emit a function name (text) that the caller saw followed by "(".

        Allowlisted names pass, names with a known problem get their
        advice, and anything else is marked review as unknown.
        """
        if lower in FUNCTION_RENAMES:
            new = FUNCTION_RENAMES[lower]
            text = new.upper() if text.isupper() else new
            lower = new
        if lower in AUTO_FUNCTIONS:
            if lower in NULL_SEMANTICS_NOTES:
                self.note(NULL_SEMANTICS_NOTES[lower])
        elif lower in REVIEW_FUNCTIONS:
            self.note(f"{text}(...) needs a hand translation. "
                      f"{REVIEW_FUNCTIONS[lower]}", review=True)
        else:
            self.note(f"The function {text}(...) is not in the "
                      "allowlist of functions that behave the same in "
                      "BigQuery; check its BigQuery equivalent by "
                      "hand.", review=True)
        out.append(_item(kind, text, fn=True))
        return i + 1

    def _in_extract(self, out):
        """True when out ends with "extract (" (the field comes next)."""
        j = _prev_sig(out)
        if j < 0 or out[j]["k"] != "open":
            return False
        k = j - 1
        while k >= 0 and out[k]["k"] == "ws":
            k -= 1
        return k >= 0 and out[k].get("fn") \
            and out[k]["t"].lower() == "extract"

    def _extract_field(self, out, text, lower):
        """Emit the EXTRACT field word, renaming or flagging it as needed."""
        if lower in EXTRACT_PASS:
            out.append(_item("word", text))
        elif lower in EXTRACT_RENAME:
            new = EXTRACT_RENAME[lower]
            self.note(f"EXTRACT({text} FROM ...) became EXTRACT({new} FROM "
                      f"...): PostgreSQL {lower} is the ISO 8601 week "
                      "number, and BigQuery WEEK counts Sunday-based weeks "
                      "starting at 0.")
            out.append(_item("word", new))
        elif lower in EXTRACT_REVIEW:
            self.note(f"EXTRACT({text} FROM ...) has no matching BigQuery "
                      f"part; write {EXTRACT_REVIEW[lower]}.", review=True)
            out.append(_item("word", text))
        else:
            self.note(f"EXTRACT({text} FROM ...) uses a field the "
                      "translator does not know; check BigQuery's EXTRACT "
                      "parts by hand.", review=True)
            out.append(_item("word", text))

    def _value_word(self, out, tokens, i, lower, nxt, next_tok, depth):
        """Rewrite a word that stands for a value; None when it is not one.

        Covers TRUE and FALSE, the identity words, CURRENT_DATE and its
        relatives, now() and friends, typed literals (date '...'), and
        the ANY, ALL, SOME quantifiers.
        """
        text = tokens[i][1]
        if lower in ("true", "false"):
            out.append(_item("atom", lower.upper(), bq="BOOL"))
            return i + 1
        if lower in IDENTITY_WORDS:
            self.note(IDENTITY_NOTE.format(word=lower))
            out.append(_item("atom", "SESSION_USER()", bq="STRING"))
            return i + 1
        if lower in SPECIAL_WORDS:
            repl, bq = SPECIAL_WORDS[lower]
            end = i + 1
            if next_tok == ("paren", "("):
                close = _match(tokens, nxt, "(", ")")
                if close is not None:
                    end = close + 1
                    self.note(f"The precision argument of {text}(...) was "
                              "dropped; BigQuery timestamps carry "
                              "microseconds.")
            out.append(_item("atom", repl, bq=bq))
            return end
        if lower in TIMESTAMP_FUNCTIONS and next_tok == ("paren", "("):
            close = _match(tokens, nxt, "(", ")")
            if close is not None and _skip_ws(tokens, nxt + 1) == close:
                out.append(_item("atom", "CURRENT_TIMESTAMP()",
                                 bq="TIMESTAMP"))
                return close + 1
        if lower in TYPED_LITERAL_WORDS and next_tok[0] == "string" \
                and next_tok[1][0] == "'":
            body = next_tok[1][1:-1].replace("''", "'")
            lit_item = _item("atom", _bq_string(body), lit=body,
                             bq="STRING")
            if lower == "interval":
                out.append(self._interval(lit_item, f"{text} {next_tok[1]}"))
                return nxt + 1
            target = bq_types.cast_type_name(lower)
            if target in LITERAL_SHAPES:
                if not LITERAL_SHAPES[target].match(body.strip()):
                    self.note(f"The literal '{body}' is not an ISO 8601 "
                              f"value; BigQuery {target} literals accept "
                              "only that form.", review=True)
                out.append(_item("atom", f"{target} {_bq_string(body)}",
                                 bq=target))
                return nxt + 1
        if lower in ("any", "all", "some") and next_tok == ("paren", "(") \
                and _prev_sig_word(out) not in SET_OPERATORS:
            return self._any_all(out, tokens, i, nxt, depth)
        return None

    def _word(self, out, tokens, i, frames, base_depth):
        text = tokens[i][1]
        lower = text.lower()
        n = len(tokens)
        depth = base_depth + len(frames)
        nxt = _skip_ws(tokens, i + 1)
        next_tok = tokens[nxt] if nxt < n else (None, None)
        if self._strip_pg_catalog(out):
            after_dot = False
        else:
            prev = _prev_sig(out)
            after_dot = prev >= 0 and out[prev]["k"] == "op" \
                and out[prev]["t"] == "."

        if self._in_extract(out) and next_tok[0] == "word" \
                and next_tok[1].lower() == "from":
            self._extract_field(out, text, lower)
            return i + 1
        # A word after a dot is a column or a schema-qualified function
        # name, never a keyword-like value such as t.current_user.
        if not after_dot:
            i2 = self._value_word(out, tokens, i, lower, nxt, next_tok,
                                  depth)
            if i2 is not None:
                return i2
        if lower == "as" and frames and frames[-1] == "cast":
            type_text, is_array, raw, k, _ = self._read_type(tokens, i + 1)
            target = None if (type_text is None or is_array) \
                else bq_types.cast_type_name(type_text)
            if target is None:
                if type_text is not None:
                    self.note(f"The cast to {raw} has no BigQuery type "
                              "mapping; pick the BigQuery type by hand.",
                              review=True)
                out.append(_item("word", text))
                return i + 1
            if target == "JSON":
                self.note(f"CAST(... AS {raw}) needs a hand translation: "
                          "BigQuery CAST(x AS JSON) turns a STRING into a "
                          "JSON string value rather than parsing it, so "
                          "write PARSE_JSON(x) for text and TO_JSON(x) for "
                          "structured values.", review=True)
            out.append(_item("word", text))
            out.append(_item("ws", " "))
            out.append(_item("word", target))
            return k
        if lower in SET_OPERATORS:
            follower = next_tok[1].lower() if next_tok[0] == "word" else ""
            if follower not in ("all", "distinct"):
                word = "DISTINCT" if text.isupper() else "distinct"
                self.note(f"{text} became {text} {word}: BigQuery requires "
                          "ALL or DISTINCT after a set operator, and "
                          f"PostgreSQL {text} without ALL removes "
                          "duplicates.")
                out.append(_item("word", f"{text} {word}"))
                return i + 1
        if lower == "on" and _prev_sig_word(out) == "distinct":
            self.note("DISTINCT ON has no BigQuery form; rewrite it with "
                      "ROW_NUMBER() OVER (PARTITION BY ...) = 1 or "
                      "ARRAY_AGG(... LIMIT 1).", review=True)
        elif lower == "zone" and _prev_sig_word(out) == "time" \
                and _prev_sig_word(out, 2) == "at":
            self.note("AT TIME ZONE has no BigQuery operator; use "
                      "DATETIME(ts, 'zone') or TIMESTAMP(dt, 'zone').",
                      review=True)
        elif lower == "similar":
            self.note("SIMILAR TO has no BigQuery form; rewrite it with "
                      "REGEXP_CONTAINS() using RE2 syntax.", review=True)
        elif lower == "escape":
            self.note("LIKE ... ESCAPE has no BigQuery form; BigQuery LIKE "
                      "always escapes with a backslash.", review=True)
        elif lower == "collate":
            self.note("COLLATE clauses differ between engines; BigQuery "
                      "supports only 'und:ci' and binary collation.",
                      review=True)
        elif lower == "filter" and next_tok == ("paren", "("):
            self.note("Aggregate FILTER (WHERE ...) has no BigQuery form; "
                      "use COUNTIF() or an IF() inside the aggregate.",
                      review=True)
        elif lower == "select" and depth > 0:
            self.note("The expression contains a subquery or CTE body: "
                      "allowed in a view, but BigQuery row access policies "
                      "allow subqueries only in limited forms, so confirm "
                      "it by hand.", review=True)
        elif lower == "symmetric" and _prev_sig_word(out) == "between":
            self.note("BETWEEN SYMMETRIC has no BigQuery form; write "
                      "x BETWEEN LEAST(a, b) AND GREATEST(a, b).",
                      review=True)
        elif lower in ("isnull", "notnull") and next_tok != ("paren", "("):
            self.note(f"x {text} is PostgreSQL shorthand with no BigQuery "
                      f"form; write x IS {'NOT ' if lower == 'notnull' else ''}"
                      "NULL.", review=True)
        elif lower == "only" and _prev_sig_word(out) in ("from", "join"):
            self.note("FROM ONLY has no BigQuery form (BigQuery has no "
                      "table inheritance); drop ONLY by hand.", review=True)
        elif lower == "from" and frames and frames[-1] == "trim":
            self.note("TRIM(BOTH x FROM y) is PostgreSQL syntax; BigQuery "
                      "writes TRIM(y, x), LTRIM(y, x) for LEADING and "
                      "RTRIM(y, x) for TRAILING.", review=True)
        elif lower in ("ilike", "like"):
            quantified = next_tok[0] == "word" \
                and next_tok[1].lower() in ("any", "all", "some")
            if lower == "ilike" or quantified:
                negated = _prev_sig_word(out) == "not"
                if negated:
                    j = _prev_sig(out)
                    del out[j:]
                fallback = f"NOT {text}" if negated else text
                if quantified:
                    return self._like_quantified(
                        out, tokens, nxt, negated, lower == "ilike", depth,
                        fallback=fallback)
                return self._like(out, tokens, i + 1, negated, depth,
                                  fallback=fallback)
        elif lower in ("b", "x") and i + 1 < n and tokens[i + 1][0] == "string":
            self.note("Bit string and hex string literals have no BigQuery "
                      "form; rewrite the literal by hand.", review=True)

        # left and right are keywords (LEFT JOIN) and also allowlisted
        # functions; followed by "(" they can only be the function.
        if next_tok == ("paren", "(") \
                and (lower not in KEYWORDS or lower in AUTO_FUNCTIONS):
            return self._function(out, i, text, lower)
        if lower in KEYWORDS or after_dot:
            out.append(_item("word", text))
            return i + 1
        return self._qualify_word(out, tokens, i)

    def _any_all(self, out, tokens, i, open_idx, depth):
        """Handle ANY, ALL, or SOME followed by "(".

        = ANY and <> ALL over an ARRAY literal become IN and NOT IN. The
        LIKE family never reaches here (see _like_quantified). Every
        other operator is marked review with the rewrite spelled out,
        since BigQuery has no quantified comparison operators.
        """
        text = tokens[i][1]
        lower = text.lower()
        prev = _prev_sig(out)
        op = None
        if prev >= 0 and out[prev]["k"] == "op":
            op = out[prev]["t"]
        pattern = self._array_arg(tokens, open_idx)
        if op in ("=", "<>", "!="):
            if pattern:
                wants_in = (op == "=" and lower in ("any", "some")) \
                    or (op in ("<>", "!=") and lower == "all")
                if wants_in:
                    del out[prev:]
                    elems = self.run(tokens[pattern[0]:pattern[1]],
                                     base_depth=depth).strip()
                    out.append(_item("word",
                                     "NOT IN" if op != "=" else "IN"))
                    out.append(_item("ws", " "))
                    out.append(_item("open", "("))
                    out.append(_item("atom", elems))
                    out.append(_item("close", ")"))
                    return pattern[2]
                self.note(f"{op} {text} (ARRAY[...]) is not an IN list "
                          "(it compares against every element or any "
                          "element with the opposite sense); rewrite it by "
                          "hand.", review=True)
            else:
                self.note(f"{text} (...) over something other than an "
                          "ARRAY literal has no direct BigQuery form; for "
                          "an array column write x IN UNNEST(arr), for a "
                          "subquery write x IN (SELECT ...).", review=True)
        elif op is not None:
            self.note(f"The operator {op} before {text} (...) has no "
                      "BigQuery form; write x IN UNNEST(arr) for an "
                      "equality test, EXISTS (SELECT 1 FROM UNNEST(arr) AS "
                      f"e WHERE x {op} e) for other comparisons, or x LIKE "
                      "ANY (...) for pattern matches.", review=True)
        else:
            self.note(f"{text} (...) follows something the translator does "
                      "not recognize as an operator; rewrite the quantified "
                      "comparison by hand (x IN UNNEST(arr) or EXISTS over "
                      "UNNEST).", review=True)
        out.append(_item("word", text))
        return i + 1

    def _in_from_list(self, out):
        """True when the next word sits in table position of a FROM list.

        Scans back over the output at the current nesting level for the
        clause the word belongs to. FROM and JOIN mean a table; any other
        clause word means a column or alias, as does running out of
        input. Parentheses that are still open are crossed, because
        pg_get_viewdef wraps join trees in them: FROM (orders o JOIN ...).
        """
        if not self.has_from:
            return False
        depth = 0
        for j in range(len(out) - 1, -1, -1):
            it = out[j]
            kind = it["k"]
            if kind in ("close", "cbracket"):
                depth += 1
            elif kind in ("open", "obracket"):
                if depth > 0:
                    depth -= 1
            elif depth == 0 and kind == "word":
                word = it["t"].lower()
                if word == "from" and _prev_sig_word(out[:j]) == "distinct":
                    return False
                if word in ("from", "join"):
                    # extract(year FROM x) and its relatives use FROM as
                    # syntax; the word after it is a value
                    return self._enclosing_fn(out, j) \
                        not in FROM_SYNTAX_FUNCTIONS
                if word in CLAUSE_STOP_WORDS:
                    return False
        return False

    @staticmethod
    def _enclosing_fn(out, j):
        """Lower-cased name of the function call enclosing out[j], or None."""
        depth = 0
        for k in range(j - 1, -1, -1):
            kind = out[k]["k"]
            if kind == "close":
                depth += 1
            elif kind == "open":
                if depth > 0:
                    depth -= 1
                    continue
                p = k - 1
                while p >= 0 and out[p]["k"] == "ws":
                    p -= 1
                if p >= 0 and out[p].get("fn"):
                    return out[p]["t"].strip("`").lower()
                return None
        return None

    def _is_alias_position(self, out):
        """True when out ends with "FROM t" or "JOIN t" or ", t" (t a table).

        The next word is then an alias, whatever it is named.
        """
        j = _prev_sig(out)
        if j < 0 or out[j]["k"] not in ("word", "atom", "qident", "close"):
            return False
        if out[j]["k"] == "word" and out[j]["t"].lower() in KEYWORDS:
            return False
        # an unmapped schema.table stays a dotted chain of words
        while j >= 2 and out[j]["k"] in ("word", "qident") \
                and out[j - 1]["k"] == "op" and out[j - 1]["t"] == "." \
                and out[j - 2]["k"] in ("word", "qident"):
            j -= 2
        k = j - 1
        while k >= 0 and out[k]["k"] == "ws":
            k -= 1
        if out[j]["k"] == "close":
            depth = 0
            for k in range(j, -1, -1):
                if out[k]["k"] == "close":
                    depth += 1
                elif out[k]["k"] == "open":
                    depth -= 1
                    if depth == 0:
                        break
            else:
                return False
            k -= 1
            while k >= 0 and out[k]["k"] == "ws":
                k -= 1
        if k < 0:
            return False
        before = out[k]
        # pg_get_viewdef wraps join trees in parentheses: FROM (t a JOIN
        return (before["k"] == "word"
                and before["t"].lower() in ("from", "join", "only")) \
            or (before["k"] == "op" and before["t"] == ",") \
            or before["k"] == "open"

    def _table_position(self, out):
        """True when the next name sits in table position of a FROM list."""
        return _prev_sig_word(out) != "as" and self._in_from_list(out) \
            and not self._is_alias_position(out)

    def _qualify_word(self, out, tokens, i):
        text = tokens[i][1]
        return self._qualify_ref(out, tokens, i, text, _item("word", text))

    def _qualify_ref(self, out, tokens, i, name, plain):
        """Replace a table name in FROM or JOIN position with its target name.

        name is the source-side spelling of the word or quoted identifier
        at tokens[i]; plain is the item to emit when it is not a table.
        A name that merely equals a table name is left alone when it is
        not in table position: a predicate with no FROM clause, a select
        list entry, an alias. A schema.table pair (either part quoted) is
        looked up as a whole.
        """
        n = len(tokens)
        if not self._table_position(out):
            out.append(plain)
            return i + 1
        chained = i + 2 < n and tokens[i + 1] == ("op", ".") \
            and tokens[i + 2][0] in ("word", "qident")
        if chained:
            dotted = f"{name}.{_unquote(tokens[i + 2])}"
            full = self.qualify(dotted)
            if full:
                out.append(_item("atom", full))
                return i + 3
            self._unmapped(dotted)
            out.append(plain)
            return i + 1
        if i + 1 < n and tokens[i + 1] == ("op", "."):
            out.append(plain)
            return i + 1
        full = self.qualify(name)
        if full:
            out.append(_item("atom", full))
            return i + 1
        self._unmapped(name)
        out.append(plain)
        return i + 1

    def _unmapped(self, name):
        """Flag a table reference that the migration inventory lacks."""
        if not self.tables or name.lower() in self.cte_names:
            return
        self.note(f"The table {name} is not in the migration inventory, so "
                  "BigQuery would resolve it against the default dataset "
                  "or fail; add it to the migration or rewrite the "
                  "reference by hand.", review=True)

    # -- operand type checks ----------------------------------------------

    def _family(self, items):
        """BigQuery type of the operand items, or None when unknown.

        Typed atoms carry it; a column reference is looked up in the
        context; number literals are INT64 or FLOAT64 by spelling; a
        date, datetime, or timestamp plus or minus an INTERVAL keeps its
        family (DATE becomes DATETIME, as in BigQuery); arithmetic over
        known numeric operands is non-integer when any operand is.
        """
        items = _strip_ws_items(items)
        while _is_group(items):
            items = _strip_ws_items(items[1:-1])
        if not items:
            return None
        if len(items) == 1:
            it = items[0]
            if it.get("bq"):
                return it["bq"]
            if it["k"] == "number":
                return "FLOAT64" if any(c in it["t"] for c in ".eE") \
                    else "INT64"
            if it["k"] in ("word", "qident"):
                return self.column_type(it["t"])
            return None
        if items[0]["k"] == "op" and items[0]["t"] == "-" \
                and len(items) == 2 and items[1]["k"] == "number":
            return self._family(items[1:])
        dotted = len(items) % 2 == 1 and all(
            (it["k"] == "op" and it["t"] == ".") if idx % 2 else
            it["k"] in ("word", "qident", "atom")
            for idx, it in enumerate(items))
        if dotted:
            return self.column_type(items[-1]["t"])
        # split at the last top-level arithmetic operator
        depth, split = 0, None
        for idx, it in enumerate(items):
            if it["k"] in ("open", "obracket"):
                depth += 1
            elif it["k"] in ("close", "cbracket"):
                depth -= 1
            elif depth == 0 and it["k"] == "op" \
                    and it["t"] in ("+", "-", "*", "/") and idx > 0:
                split = idx
        if split is None:
            return None
        op = items[split]["t"]
        left = self._family(items[:split])
        right = self._family(items[split + 1:])
        if "INTERVAL" in (left, right) and op in ("+", "-"):
            other = right if left == "INTERVAL" else left
            if other == "DATE":
                return "DATETIME"
            return other if other in TEMPORAL_TYPES else None
        if left is None or right is None:
            return None
        if op == "/":
            return "FLOAT64"
        for fam in (left, right):
            if fam in NON_INTEGER_TYPES:
                return fam
        return "INT64" if left == right == "INT64" else None

    def _operand_before(self, out, idx):
        j = _prev_sig(out[:idx])
        start = _atom_start(out, j)
        return None if start is None else out[start:j + 1]

    def _operand_after(self, out, idx):
        k = idx + 1
        while k < len(out) and out[k]["k"] == "ws":
            k += 1
        end = _atom_finish(out, k)
        return None if end is None else out[k:end + 1]

    def _check_operators(self, out):
        """Type checks that need both operands: temporal families and /."""
        for idx, it in enumerate(out):
            if it["k"] != "op" or it["t"] not in COMPARE_OPS | {"/"}:
                continue
            left = self._operand_before(out, idx)
            right = self._operand_after(out, idx)
            if left is None or right is None:
                continue
            lf, rf = self._family(left), self._family(right)
            if it["t"] == "/":
                if lf in NON_INTEGER_TYPES or rf in NON_INTEGER_TYPES:
                    continue
                self.note(f"The division {_join(left).strip()} / "
                          f"{_join(right).strip()} needs a hand check: "
                          f"{DIVISION_NOTE}", review=True)
                continue
            if lf in TEMPORAL_TYPES or rf in TEMPORAL_TYPES:
                self._check_temporal(left, lf, it["t"], right, rf)

    def _check_temporal(self, left, lf, op, right, rf):
        """Note a date, datetime, or timestamp comparison BigQuery rejects.

        BigQuery coerces DATE to DATETIME and nothing else across these
        three types, while PostgreSQL casts freely between them.
        """
        shown = f"{_join(left).strip()} {op} {_join(right).strip()}"
        if lf in TEMPORAL_TYPES and rf in TEMPORAL_TYPES:
            if lf == rf or {lf, rf} == {"DATE", "DATETIME"}:
                return
            col = None
            for items, fam in ((left, lf), (right, rf)):
                if _is_column_ref(items):
                    col = (_join(items).strip(), fam)
            if col and col[1] == "TIMESTAMP":
                fix = (f"DATETIME({col[0]}, zone) or DATE({col[0]}, zone) "
                       "(PostgreSQL used the session time zone), or make "
                       "the other side a TIMESTAMP")
            elif col:
                fix = (f"TIMESTAMP({col[0]}, zone) (PostgreSQL used the "
                       "session time zone), or use CURRENT_DATETIME(), "
                       "CURRENT_DATE(), or a DATETIME literal on the other "
                       "side")
            else:
                fix = ("TIMESTAMP(x, zone), DATETIME(ts, zone), or "
                       "DATE(ts, zone) on one side")
            self.note(f"The comparison {shown} mixes {lf} and {rf}; "
                      "BigQuery has no implicit conversion between them "
                      "(PostgreSQL casts across these types), so write "
                      f"{fix}.", review=True)
            return
        # one side is a column whose type the context did not give
        for items, fam, other in ((left, lf, rf), (right, rf, lf)):
            if fam is None and other in TEMPORAL_TYPES \
                    and _is_column_ref(items):
                name = _join(items).strip()
                if other == "TIMESTAMP":
                    ok = "TIMESTAMP (PostgreSQL timestamp with time zone)"
                    wrap = (f"TIMESTAMP({name}, zone) for a DATETIME or "
                            "DATE column, or CURRENT_DATETIME() in place "
                            "of CURRENT_TIMESTAMP()")
                else:
                    ok = ("DATE or DATETIME (PostgreSQL date or timestamp "
                          "without time zone)")
                    wrap = f"DATE({name}, zone) or DATETIME({name}, zone) " \
                           "for a TIMESTAMP column"
                self.note(f"{name} is compared with a {other} value, which "
                          f"BigQuery accepts only when the column is {ok}; "
                          "the translator was not given the column's type "
                          "(context columns with bq_type or inventory "
                          f"fields), so confirm it and write {wrap} if it "
                          "differs.")


def _has_from(tokens):
    """True when a FROM or JOIN opens a table list somewhere in tokens.

    IS DISTINCT FROM and the FROM inside extract(...), substring(...),
    trim(...), overlay(...), and position(...) are syntax, not table
    lists, and do not count.
    """
    stack = []
    prev = None
    for kind, text in tokens:
        if kind == "ws":
            continue
        if kind == "paren":
            if text == "(":
                name = None
                if prev and prev[0] in ("word", "qident"):
                    name = _unquote(prev).lower()
                stack.append(name)
            elif stack:
                stack.pop()
        elif kind == "word":
            lower = text.lower()
            if lower == "join":
                return True
            if lower == "from":
                after_distinct = prev is not None and prev[0] == "word" \
                    and prev[1].lower() == "distinct"
                inside_fn = bool(stack) and stack[-1] in FROM_SYNTAX_FUNCTIONS
                if not after_distinct and not inside_fn:
                    return True
        prev = (kind, text)
    return False


def _cte_names(tokens):
    """Lower-cased names bound by WITH: every name before AS ( ... )."""
    names = set()
    sig = [(k, t) for k, t in tokens if k != "ws"]
    for idx in range(1, len(sig) - 1):
        kind, text = sig[idx]
        if kind != "word" or text.lower() != "as" \
                or sig[idx + 1] != ("paren", "("):
            continue
        k = idx - 1
        if sig[k] == ("paren", ")"):
            # WITH x(a, b) AS (...): skip the column list
            depth = 0
            while k >= 0:
                if sig[k] == ("paren", ")"):
                    depth += 1
                elif sig[k] == ("paren", "("):
                    depth -= 1
                    if depth == 0:
                        break
                k -= 1
            k -= 1
        if k >= 0 and sig[k][0] in ("word", "qident") \
                and _unquote(sig[k]).lower() not in KEYWORDS:
            names.add(_unquote(sig[k]).lower())
    return names


def translate(expr, context=None):
    """Translate a PostgreSQL expression or SELECT body to BigQuery SQL.

    Returns {"sql": str, "confidence": "auto" | "review", "notes": [str]}.
    Never raises: unparseable input comes back unchanged with confidence
    "review" and a note saying why.

    expr is expected in pg_get_expr or pg_get_viewdef form: fully
    parenthesized, literals with explicit ::type casts, keyword-named
    functions double quoted. Hand-written SQL is accepted, but constructs
    that ruleutils never emits may come back marked review.

    With confidence "review", sql is still a partial translation: every
    recognized construct is rewritten and only the construct named in
    the notes keeps its PostgreSQL form. It is a starting point for the
    reviewer, not the original text (the original is the caller's).

    context["tables"] maps bare and schema-qualified source names to the
    target name; a word is replaced only in table position (after FROM
    or JOIN, or after a comma in a FROM list), never in a predicate with
    no FROM clause. A table in that position that the map lacks is
    marked review (a reference BigQuery cannot resolve), so the map
    should carry every table, view, and materialized view the migration
    creates. context["columns"] entries may carry the column's BigQuery
    type ({"name", "bq_type"} or an inventory column dict); with it, a
    comparison that mixes DATE, DATETIME, and TIMESTAMP families and an
    integer division are detected exactly instead of by note.
    """
    expr = "" if expr is None else str(expr)
    try:
        tokens = tokenize(expr)
    except TokenizeError as exc:
        return {"sql": expr.strip(), "confidence": "review",
                "notes": [f"The expression could not be tokenized ({exc}); "
                          "translate it by hand."]}
    tr = _Translator(context)
    tr.has_from = _has_from(tokens)
    tr.cte_names = _cte_names(tokens)
    try:
        sql = tr.run(tokens).strip()
    except Exception as exc:  # last resort: the pipeline must not crash
        return {"sql": expr.strip(), "confidence": "review",
                "notes": [f"The translator failed on this expression "
                          f"({type(exc).__name__}: {exc}); translate it "
                          "by hand."]}
    if not sql:
        tr.note("The expression is empty; nothing to translate.",
                review=True)
    return {"sql": sql,
            "confidence": "review" if tr.review else "auto",
            "notes": list(tr.notes)}
