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

The same translator serves row-level security predicates (pg_get_expr
output) and view bodies (pg_get_viewdef output).
"""
import re

from db_drift import bq_types

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
    if items[0]["k"] == "word" and items[0].get("fn") \
            and _is_group(items[1:]):
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


def _pop_atom(out):
    """Remove and return the items forming the atom that ends out.

    Trailing whitespace is removed too. Returns None when out does not end
    with something atom-shaped (for example an operator).
    """
    j = _prev_sig(out)
    if j < 0:
        return None
    start = j
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
        start = k
        if k > 0 and out[k - 1]["k"] == "word" and (
                out[k - 1].get("fn") or (kind == "cbracket" and
                                         out[k - 1]["t"].lower() == "array")):
            start = k - 1
    elif kind in ("atom", "word", "number", "qident"):
        while start >= 2 and out[start - 1]["k"] == "op" \
                and out[start - 1]["t"] == "." \
                and out[start - 2]["k"] in ("word", "qident"):
            start -= 2
    else:
        return None
    items = out[start:j + 1]
    del out[start:]
    return items


def _bq_string(body):
    body = (body.replace("\\", "\\\\").replace("'", "\\'")
            .replace("\n", "\\n").replace("\r", "\\r"))
    return "'" + body + "'"


def _bq_ident(inner):
    inner = inner.replace("\\", "\\\\").replace("`", "\\`")
    return "`" + inner + "`"


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
        for col in ctx.get("columns") or []:
            name = col if isinstance(col, str) else (
                col.get("name") or col.get("column") or "")
            if name:
                self.columns.add(str(name).lower())
        self.notes = []
        self.review = False

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

        Returns (type_text, is_array, raw_text, next_index). type_text is
        None when no type name is there.
        """
        start = _skip_ws(tokens, k)
        k = start
        n = len(tokens)
        if k >= n or tokens[k][0] not in ("word", "qident"):
            return None, False, "", k
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
        m = _skip_ws(tokens, k)
        if m < n and tokens[m] == ("paren", "("):
            close = _match(tokens, m, "(", ")")
            if close is not None:
                k = close + 1
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
        return " ".join(words), is_array, raw, k

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
            if lower == "array" and m < n and tokens[m] == ("op", "["):
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
                        and lower not in KEYWORDS:
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
        else:
            return None
        while True:
            m = _skip_ws(tokens, k)
            if m < n and tokens[m] == ("op", "::"):
                type_text, _, _, k2 = self._read_type(tokens, m + 1)
                if type_text is None:
                    return k
                k = k2
            else:
                return k

    # -- main pass ---------------------------------------------------------

    def run(self, tokens, base_depth=0):
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
                    if j >= 0 and out[j]["k"] == "word" and out[j].get("fn"):
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
                out.append(_item("qident", _bq_ident(inner)))
                i += 1
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
        return _join(out)

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
        type_text, is_array, raw, k = self._read_type(tokens, i + 1)
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
            out.append(self._interval(single, original))
            return k
        target = bq_types.cast_type_name(pg)
        if target is None:
            self.note(f"The cast to {raw} has no BigQuery type mapping; "
                      "pick the BigQuery type by hand.", review=True)
            out.append(_item("atom", original))
            return k
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

    def _interval(self, single, original):
        lit = single.get("lit") if single else None
        m = INTERVAL_RE.match(lit.strip()) if lit is not None else None
        if not m:
            shown = f"'{lit}'" if lit is not None else original
            self.note(f"The interval {shown} is not in the form "
                      "'N unit' that translates to INTERVAL N UNIT; write "
                      "the BigQuery interval by hand.", review=True)
            return _item("atom", original)
        return _item("atom", f"INTERVAL {int(m.group(1))} "
                             f"{m.group(2).upper()}", bq="INTERVAL")

    def _like(self, out, tokens, j, negated, depth, fallback):
        """Emit LOWER(lhs) [NOT] LIKE LOWER(rhs); j is after the operator."""
        j = _skip_ws(tokens, j)
        k = self._atom_end(tokens, j)
        lhs = _pop_atom(out)
        if lhs is None or k is None:
            self.note("A case-insensitive LIKE has a missing operand; "
                      "translate it by hand.", review=True)
            if lhs:
                out.extend(lhs)
            out.append(_item("op", fallback))
            return j
        single = _single_item(lhs)
        lhs_text = single["t"] if single else _join(_collapse_parens(lhs))
        rhs_text = self.run(tokens[j:k], base_depth=depth).strip()
        op = "NOT LIKE" if negated else "LIKE"
        out.append(_item("atom",
                         f"LOWER({lhs_text}) {op} LOWER({rhs_text})"))
        return k

    # -- words -------------------------------------------------------------------

    def _word(self, out, tokens, i, frames, base_depth):
        text = tokens[i][1]
        lower = text.lower()
        n = len(tokens)
        depth = base_depth + len(frames)
        nxt = _skip_ws(tokens, i + 1)
        next_tok = tokens[nxt] if nxt < n else (None, None)
        prev = _prev_sig(out)
        after_dot = prev >= 0 and out[prev]["k"] == "op" \
            and out[prev]["t"] == "."
        if after_dot and prev >= 1 and out[prev - 1]["k"] == "word" \
                and out[prev - 1]["t"].lower() == "pg_catalog":
            del out[prev - 1:]
            prev = _prev_sig(out)
            after_dot = False

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
        if lower in ("any", "all", "some") and next_tok == ("paren", "("):
            return self._any_all(out, tokens, i, nxt, depth)
        if lower == "as" and frames and frames[-1] == "cast":
            type_text, is_array, raw, k = self._read_type(tokens, i + 1)
            target = None if (type_text is None or is_array) \
                else bq_types.cast_type_name(type_text)
            if target is None:
                if type_text is not None:
                    self.note(f"The cast to {raw} has no BigQuery type "
                              "mapping; pick the BigQuery type by hand.",
                              review=True)
                out.append(_item("word", text))
                return i + 1
            out.append(_item("word", text))
            out.append(_item("ws", " "))
            out.append(_item("word", target))
            return k
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
            self.note("The expression contains a subquery or CTE body; "
                      "BigQuery row access policies allow subqueries only "
                      "in limited forms, so confirm it by hand.",
                      review=True)
        elif lower == "ilike":
            negated = _prev_sig_word(out) == "not"
            if negated:
                j = _prev_sig(out)
                del out[j:]
            return self._like(out, tokens, i + 1, negated, depth,
                              fallback=text)
        elif lower in ("b", "x") and i + 1 < n and tokens[i + 1][0] == "string":
            self.note("Bit string and hex string literals have no BigQuery "
                      "form; rewrite the literal by hand.", review=True)

        if next_tok == ("paren", "(") and lower not in KEYWORDS:
            if lower in AUTO_FUNCTIONS:
                pass
            elif lower in REVIEW_FUNCTIONS:
                self.note(f"{text}(...) needs a hand translation. "
                          f"{REVIEW_FUNCTIONS[lower]}", review=True)
            else:
                self.note(f"The function {text}(...) is not in the "
                          "allowlist of functions that behave the same in "
                          "BigQuery; check its BigQuery equivalent by "
                          "hand.", review=True)
            out.append(_item("word", text, fn=True))
            return i + 1
        if lower in KEYWORDS or after_dot:
            out.append(_item("word", text))
            return i + 1
        return self._qualify_word(out, tokens, i)

    def _any_all(self, out, tokens, i, open_idx, depth):
        text = tokens[i][1]
        lower = text.lower()
        n = len(tokens)
        prev = _prev_sig(out)
        op = None
        if prev >= 0 and out[prev]["k"] == "op" \
                and out[prev]["t"] in ("=", "<>", "!="):
            op = out[prev]["t"]
        j = _skip_ws(tokens, open_idx + 1)
        pattern = None
        if j < n and tokens[j][0] == "word" and tokens[j][1].lower() == "array":
            j2 = _skip_ws(tokens, j + 1)
            if j2 < n and tokens[j2] == ("op", "["):
                close_b = _match(tokens, j2, "[", "]")
                if close_b is not None:
                    j3 = _skip_ws(tokens, close_b + 1)
                    if j3 < n and tokens[j3] == ("paren", ")"):
                        pattern = (j2 + 1, close_b, j3 + 1)
        if pattern and op:
            wants_in = (op == "=" and lower in ("any", "some")) \
                or (op in ("<>", "!=") and lower == "all")
            if wants_in:
                del out[prev:]
                elems = self.run(tokens[pattern[0]:pattern[1]],
                                 base_depth=depth).strip()
                out.append(_item("word", "NOT IN" if op != "=" else "IN"))
                out.append(_item("ws", " "))
                out.append(_item("open", "("))
                out.append(_item("atom", elems))
                out.append(_item("close", ")"))
                return pattern[2]
            self.note(f"{op} {text} (ARRAY[...]) is not an IN list "
                      "(it compares against every element or any element "
                      "with the opposite sense); rewrite it by hand.",
                      review=True)
        elif pattern is None:
            self.note(f"{text} (...) over something other than an ARRAY "
                      "literal has no direct BigQuery form; for an array "
                      "column write x IN UNNEST(arr), for a subquery write "
                      "x IN (SELECT ...).", review=True)
        out.append(_item("word", text))
        return i + 1

    def _qualify_word(self, out, tokens, i):
        text = tokens[i][1]
        n = len(tokens)
        if _prev_sig_word(out) == "as":
            out.append(_item("word", text))
            return i + 1
        chained = i + 2 < n and tokens[i + 1] == ("op", ".") \
            and tokens[i + 2][0] == "word"
        if chained:
            full = self.qualify(f"{text}.{tokens[i + 2][1]}")
            if full:
                out.append(_item("atom", full))
                return i + 3
            out.append(_item("word", text))
            return i + 1
        if i + 1 < n and tokens[i + 1] == ("op", "."):
            out.append(_item("word", text))
            return i + 1
        full = self.qualify(text)
        if full and text.lower() in self.columns \
                and _prev_sig_word(out) not in ("from", "join"):
            out.append(_item("word", text))
            return i + 1
        if full:
            out.append(_item("atom", full))
            return i + 1
        out.append(_item("word", text))
        return i + 1


def translate(expr, context=None):
    """Translate a PostgreSQL expression or SELECT body to BigQuery SQL.

    Returns {"sql": str, "confidence": "auto" | "review", "notes": [str]}.
    Never raises: unparseable input comes back unchanged with confidence
    "review" and a note saying why.
    """
    expr = "" if expr is None else str(expr)
    try:
        tokens = tokenize(expr)
    except TokenizeError as exc:
        return {"sql": expr.strip(), "confidence": "review",
                "notes": [f"The expression could not be tokenized ({exc}); "
                          "translate it by hand."]}
    tr = _Translator(context)
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
