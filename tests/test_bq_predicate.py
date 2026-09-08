import pytest

from db_drift import bq_predicate as bp

TABLES = {
    "orders": "`p.retail.orders`",
    "public.orders": "`p.retail.orders`",
    "customers": "`p.retail.customers`",
    "public.customers": "`p.retail.customers`",
    "order_items": "`p.retail.order_items`",
    "public.order_items": "`p.retail.order_items`",
    "products": "`p.retail.products`",
    "public.products": "`p.retail.products`",
}


def tr(expr, tables=None, columns=None):
    ctx = None
    if tables is not None or columns is not None:
        ctx = {"tables": tables or {}, "columns": columns or []}
    return bp.translate(expr, ctx)


def kinds(sql):
    return [k for k, _ in bp.tokenize(sql)]


def texts(sql):
    return [t for _, t in bp.tokenize(sql)]


# ---------------------------------------------------------------- tokenizer

def test_tokenize_round_trips_text():
    sql = ("SELECT o.id, \"Quoted \"\"x\"\"\" FROM orders o WHERE (a ~~* "
           "'it''s'::text) AND b >= 1.5e3 OR c <> ALL (ARRAY[1, 2]) -- c\n"
           "/* block */ E'x\\n'")
    assert "".join(texts(sql)) == sql


def test_tokenize_kinds_and_longest_operator_match():
    toks = bp.tokenize("a.b::text ~~* 'x''y' !~~* \"q\" <> 12 >= .5 || [1]")
    assert toks[0] == ("word", "a")
    assert toks[1] == ("op", ".")
    assert toks[2] == ("word", "b")
    assert toks[3] == ("op", "::")
    assert toks[4] == ("word", "text")
    assert ("op", "~~*") in toks
    assert ("string", "'x''y'") in toks
    assert ("op", "!~~*") in toks
    assert ("qident", '"q"') in toks
    assert ("op", "<>") in toks
    assert ("number", "12") in toks
    assert ("op", ">=") in toks
    assert ("number", ".5") in toks
    assert ("op", "||") in toks
    assert ("op", "[") in toks and ("op", "]") in toks
    assert ("number", "1") in toks


def test_tokenize_parens_commas_and_escaped_strings():
    toks = bp.tokenize("(f(a, b))")
    assert toks[0] == ("paren", "(")
    assert toks[-1] == ("paren", ")")
    assert ("op", ",") in toks
    assert bp.tokenize("E'a\\'b'") == [("string", "E'a\\'b'")]
    assert bp.tokenize("'a''b'") == [("string", "'a''b'")]
    assert kinds("-- note\nx /* c */ y") == ["ws", "ws", "word", "ws", "ws",
                                            "ws", "word"]


def test_tokenize_regex_operators_are_single_tokens():
    for op in ("~", "~*", "!~", "!~*", "~~", "~~*", "!~~", "!~~*", "::",
               "<>", "!=", "<=", ">=", "||"):
        assert bp.tokenize(f"a {op} b")[2] == ("op", op)


def test_tokenize_unterminated_string_raises_tokenize_error():
    with pytest.raises(bp.TokenizeError):
        bp.tokenize("'open")
    with pytest.raises(bp.TokenizeError):
        bp.tokenize('"open')


# ------------------------------------------------------- plan behavior table

def test_string_literal_cast_to_text_is_dropped():
    r = tr("(region = 'eu'::text)")
    assert r == {"sql": "(region = 'eu')", "confidence": "auto", "notes": []}


def test_current_user_becomes_session_user_with_identity_note():
    r = tr("(actor = CURRENT_USER)")
    assert r["sql"] == "(actor = SESSION_USER())"
    assert r["confidence"] == "auto"
    assert len(r["notes"]) == 1
    assert "SESSION_USER()" in r["notes"][0]
    assert "email" in r["notes"][0]


def test_current_user_cast_to_text_drops_the_redundant_cast():
    r = tr("(actor = (CURRENT_USER)::text)")
    assert r["sql"] == "(actor = SESSION_USER())"
    assert r["confidence"] == "auto"


def test_session_user_and_current_role_also_map():
    assert tr("(x = session_user)")["sql"] == "(x = SESSION_USER())"
    assert tr("(x = current_role)")["sql"] == "(x = SESSION_USER())"


def test_true_and_false_are_upper_cased():
    assert tr("true") == {"sql": "TRUE", "confidence": "auto", "notes": []}
    assert tr("false")["sql"] == "FALSE"
    assert tr("(active = true)")["sql"] == "(active = TRUE)"


def test_not_equal_all_array_becomes_not_in():
    r = tr("(status <> ALL (ARRAY['cancelled'::text, 'refunded'::text]))")
    assert r["sql"] == "(status NOT IN ('cancelled', 'refunded'))"
    assert r["confidence"] == "auto"


def test_equal_any_array_becomes_in():
    r = tr("(status = ANY (ARRAY['a'::text, 'b'::text]))")
    assert r["sql"] == "(status IN ('a', 'b'))"
    assert r["confidence"] == "auto"


def test_current_setting_is_review_and_retained():
    r = tr("(tenant_id = (current_setting('app.tenant'::text))::integer)")
    # review output is a partial rewrite: the casts around the unknown
    # call are still translated, the call itself is retained
    assert r["sql"] == \
        "(tenant_id = CAST(current_setting('app.tenant') AS INT64))"
    assert r["confidence"] == "review"
    assert any("current_setting" in n for n in r["notes"])


def test_now_minus_interval_literal():
    r = tr("(ordered_at > (now() - '90 days'::interval))")
    assert r["sql"] == \
        "(ordered_at > (CURRENT_TIMESTAMP() - INTERVAL 90 DAY))"
    assert r["confidence"] == "auto"


def test_string_literal_cast_to_date_becomes_typed_literal():
    r = tr("(created_at >= '2024-01-01'::date)")
    assert r["sql"] == "(created_at >= DATE '2024-01-01')"
    assert r["confidence"] == "auto"


def test_number_cast_to_numeric_uses_cast_and_strips_parens():
    r = tr("(amount > (100)::numeric)")
    assert r["sql"] == "(amount > CAST(100 AS NUMERIC))"
    assert r["confidence"] == "auto"


def test_ilike_operator_becomes_lower_like_lower():
    r = tr("(name ~~* 'a%'::text)")
    assert r["sql"] == "(LOWER(name) LIKE LOWER('a%'))"
    assert r["confidence"] == "auto"


def test_regex_operator_is_review():
    r = tr("(name ~ '^a'::text)")
    assert r["sql"] == "(name ~ '^a')"
    assert r["confidence"] == "review"
    assert any("regular expression" in n for n in r["notes"])
    # the rest of a review expression is still rewritten
    r = tr("(a ~ 'x'::text) AND (b = 'y'::text) AND (c = CURRENT_USER)")
    assert r["sql"] == "(a ~ 'x') AND (b = 'y') AND (c = SESSION_USER())"
    assert r["confidence"] == "review"


def test_subquery_is_review_but_tables_still_qualify():
    r = tr("(id IN (SELECT id FROM allowed))",
           tables={"allowed": "`p.d.allowed`"})
    assert r["sql"] == "(id IN (SELECT id FROM `p.d.allowed`))"
    assert r["confidence"] == "review"
    assert any("subquery" in n for n in r["notes"])


def test_double_quoted_identifier_becomes_backticks():
    r = tr('"quoted col" = 1')
    assert r == {"sql": "`quoted col` = 1", "confidence": "auto",
                 "notes": []}


def test_unknown_function_is_review_and_unchanged():
    r = tr("some_func(x) = 1")
    assert r["sql"] == "some_func(x) = 1"
    assert r["confidence"] == "review"
    assert any("some_func" in n for n in r["notes"])


def test_select_body_qualifies_tables_and_translates_interval():
    src = ("SELECT o.id, c.email FROM orders o JOIN customers c "
           "ON c.id = o.customer_id "
           "WHERE o.ordered_at > (now() - '90 days'::interval)")
    r = tr(src, tables=TABLES)
    assert r["sql"] == (
        "SELECT o.id, c.email FROM `p.retail.orders` o "
        "JOIN `p.retail.customers` c ON c.id = o.customer_id "
        "WHERE o.ordered_at > (CURRENT_TIMESTAMP() - INTERVAL 90 DAY)")
    assert r["confidence"] == "auto"


# ------------------------------------------------ observed on the demo source

def test_demo_view_body():
    src = (" SELECT o.id, c.email, o.status, o.ordered_at FROM (orders o "
           "JOIN customers c ON ((c.id = o.customer_id))) WHERE "
           "(o.ordered_at > (now() - '90 days'::interval));")
    # the schema phase passes the inventory's column dicts as context
    cols = [{"schema": "public", "table": "orders", "name": "ordered_at",
             "data_type": "timestamp with time zone",
             "udt_name": "timestamptz"}]
    r = tr(src, tables=TABLES, columns=cols)
    expected = (
        "SELECT o.id, c.email, o.status, o.ordered_at FROM "
        "(`p.retail.orders` o JOIN `p.retail.customers` c "
        "ON ((c.id = o.customer_id))) WHERE "
        "(o.ordered_at > (CURRENT_TIMESTAMP() - INTERVAL 90 DAY))")
    assert r == {"sql": expected, "confidence": "auto", "notes": []}
    # without column types the comparison is still auto, with a note
    # asking the reviewer to confirm the column's family
    r = tr(src, tables=TABLES)
    assert r["sql"] == expected
    assert r["confidence"] == "auto"
    assert len(r["notes"]) == 1
    assert "o.ordered_at" in r["notes"][0] and "TIMESTAMP" in r["notes"][0]


def test_demo_matview_body():
    src = (" SELECT p.id, p.sku, sum(oi.quantity) AS qty, "
           "sum((oi.quantity * oi.unit_price_cents)) AS revenue_cents "
           "FROM (order_items oi JOIN products p ON ((p.id = oi.product_id)))"
           " GROUP BY p.id, p.sku;")
    r = tr(src, tables=TABLES)
    assert r["sql"] == (
        "SELECT p.id, p.sku, sum(oi.quantity) AS qty, "
        "sum((oi.quantity * oi.unit_price_cents)) AS revenue_cents "
        "FROM (`p.retail.order_items` oi JOIN `p.retail.products` p "
        "ON ((p.id = oi.product_id))) GROUP BY p.id, p.sku")
    assert r["confidence"] == "auto"


def test_demo_policy_expressions():
    assert tr("(region = 'eu'::text)")["sql"] == "(region = 'eu')"
    assert tr("(actor = CURRENT_USER)")["sql"] == "(actor = SESSION_USER())"
    assert tr("true")["sql"] == "TRUE"


# ------------------------------------------------------------ casts in depth

def test_timestamp_casts_become_typed_literals():
    r = tr("(t >= '2024-01-01 10:00:00+00'::timestamp with time zone)")
    assert r["sql"] == "(t >= TIMESTAMP '2024-01-01 10:00:00+00')"
    assert r["confidence"] == "auto"
    r = tr("(t >= '2024-01-01 10:00:00'::timestamp without time zone)")
    assert r["sql"] == "(t >= DATETIME '2024-01-01 10:00:00')"
    r = tr("(t >= '2024-01-01 10:00:00'::timestamp)")
    assert r["sql"] == "(t >= DATETIME '2024-01-01 10:00:00')"
    r = tr("(t >= '2024-01-01'::timestamptz)")
    assert r["sql"] == "(t >= TIMESTAMP '2024-01-01')"


def test_non_iso_date_literal_is_review():
    r = tr("(created_at >= 'now'::date)")
    assert r["sql"] == "(created_at >= DATE 'now')"
    assert r["confidence"] == "review"
    assert any("'now'" in n for n in r["notes"])


def test_cast_of_expression_keeps_parens_and_maps_type():
    r = tr("((a + b))::double precision")
    assert r["sql"] == "CAST((a + b) AS FLOAT64)"
    assert r["confidence"] == "auto"
    r = tr("(o.total)::character varying(20)")
    assert r["sql"] == "CAST(o.total AS STRING)"
    r = tr("(now())::date")
    assert r["sql"] == "CAST(CURRENT_TIMESTAMP() AS DATE)"
    r = tr("(\"col\")::bigint")
    assert r["sql"] == "CAST(`col` AS INT64)"


def test_chained_casts():
    r = tr("(('1'::text))::integer")
    assert r["sql"] == "CAST('1' AS INT64)"
    assert r["confidence"] == "auto"


def test_redundant_cast_to_same_type_is_dropped():
    assert tr("(now())::timestamp with time zone")["sql"] \
        == "CURRENT_TIMESTAMP()"
    assert tr("'abc'::uuid")["sql"] == "'abc'"
    assert tr("'abc'::character varying")["sql"] == "'abc'"


def test_unknown_and_array_casts_are_review():
    r = tr("(x)::regclass")
    assert r["confidence"] == "review"
    assert "regclass" in r["sql"]
    assert any("regclass" in n for n in r["notes"])
    r = tr("(tags)::text[]")
    assert r["confidence"] == "review"
    assert "text[]" in r["sql"]
    assert any("array" in n.lower() for n in r["notes"])


def test_interval_forms():
    assert tr("'1 hour'::interval")["sql"] == "INTERVAL 1 HOUR"
    assert tr("'2 weeks'::interval")["sql"] == "INTERVAL 2 WEEK"
    assert tr("interval '30 minutes'")["sql"] == "INTERVAL 30 MINUTE"
    r = tr("'1 day 02:00:00'::interval")
    assert r["confidence"] == "review"
    assert "'1 day 02:00:00'" in r["sql"]
    assert any("interval" in n for n in r["notes"])


def test_word_form_cast_maps_the_type_name():
    r = tr("CAST(x AS integer) = 1")
    assert r["sql"] == "CAST(x AS INT64) = 1"
    assert r["confidence"] == "auto"
    r = tr("cast(x as text)")
    assert r["sql"] == "cast(x as STRING)"
    r = tr("CAST(x AS regclass)")
    assert r["confidence"] == "review"
    assert "regclass" in r["sql"]


def test_typed_literal_words():
    assert tr("d = date '2024-02-03'")["sql"] == "d = DATE '2024-02-03'"
    assert tr("t = timestamp '2024-02-03 04:05:06'")["sql"] \
        == "t = DATETIME '2024-02-03 04:05:06'"


# ------------------------------------------------------- like and regex forms

def test_like_family_operators():
    assert tr("(name ~~ 'a%'::text)")["sql"] == "(name LIKE 'a%')"
    assert tr("(name !~~ 'a%'::text)")["sql"] == "(name NOT LIKE 'a%')"
    assert tr("(name !~~* 'a%'::text)")["sql"] \
        == "(LOWER(name) NOT LIKE LOWER('a%'))"
    assert tr("(name ~~* upper(x))")["sql"] \
        == "(LOWER(name) LIKE LOWER(upper(x)))"


def test_ilike_word_forms():
    r = tr("name ILIKE 'a%'")
    assert r["sql"] == "LOWER(name) LIKE LOWER('a%')"
    assert r["confidence"] == "auto"
    r = tr("o.name NOT ILIKE 'a%'")
    assert r["sql"] == "LOWER(o.name) NOT LIKE LOWER('a%')"
    assert tr("name LIKE 'a%'")["sql"] == "name LIKE 'a%'"


def test_regex_family_and_similar_to_are_review():
    for op in ("~*", "!~", "!~*"):
        r = tr(f"(name {op} 'x'::text)")
        assert r["confidence"] == "review"
        assert f" {op} " in r["sql"]
    r = tr("name SIMILAR TO 'a%'")
    assert r["confidence"] == "review"
    assert any("SIMILAR TO" in n for n in r["notes"])


def test_like_escape_clause_is_review():
    r = tr("name LIKE 'a#%' ESCAPE '#'")
    assert r["confidence"] == "review"
    assert any("ESCAPE" in n for n in r["notes"])


# ---------------------------------------------------------- any and all forms

def test_any_all_variants_without_in_semantics_are_review():
    r = tr("(x = ALL (ARRAY[1, 2]))")
    assert r["confidence"] == "review"
    assert "ALL" in r["sql"]
    r = tr("(x <> ANY (ARRAY[1, 2]))")
    assert r["confidence"] == "review"
    r = tr("(x = ANY (allowed_ids))")
    assert r["confidence"] == "review"
    assert "ANY (allowed_ids)" in r["sql"]
    assert any("UNNEST" in n for n in r["notes"])


def test_union_all_is_not_touched():
    r = tr("SELECT 1 UNION ALL SELECT 2")
    assert r["sql"] == "SELECT 1 UNION ALL SELECT 2"
    assert r["confidence"] == "auto"


def test_any_over_numbers_with_casts():
    r = tr("(id = ANY (ARRAY[(1)::bigint, (2)::bigint]))")
    assert r["sql"] == "(id IN (CAST(1 AS INT64), CAST(2 AS INT64)))"
    assert r["confidence"] == "auto"


def test_plain_in_list_passes_through():
    r = tr("(status IN ('a', 'b'))")
    assert r["sql"] == "(status IN ('a', 'b'))"
    assert r["confidence"] == "auto"


# ------------------------------------------------------- strings and idents

def test_string_literal_escaping_for_bigquery():
    assert tr("x = 'it''s'")["sql"] == "x = 'it\\'s'"
    assert tr("x = 'a\\b'")["sql"] == "x = 'a\\\\b'"
    r = tr("x = E'a\\nb'")
    assert r["sql"] == "x = 'a\\nb'"
    assert r["confidence"] == "review"
    assert any("E'" in n for n in r["notes"])


def test_dollar_quoted_string_is_review():
    r = tr("x = $$abc$$")
    assert r["confidence"] == "review"
    assert "$$abc$$" in r["sql"]


def test_quoted_identifier_escaping_and_chains():
    assert tr('"a""b" = 1')["sql"] == "`a\"b` = 1"
    assert tr('"s"."t"."c" = 1')["sql"] == "`s`.`t`.`c` = 1"
    assert tr('"back`tick" = 1')["sql"] == "`back\\`tick` = 1"


def test_keyword_case_is_preserved_except_booleans():
    assert tr("a and b or NOT c")["sql"] == "a and b or NOT c"
    assert tr("a AND b")["sql"] == "a AND b"
    assert tr("x is null")["sql"] == "x is null"


# ------------------------------------------------------ table qualification

def test_qualification_rules():
    assert tr("SELECT 1 FROM public.orders", tables=TABLES)["sql"] \
        == "SELECT 1 FROM `p.retail.orders`"
    # column qualifier words are not tables even when they match a name
    assert tr("SELECT orders.id FROM orders", tables=TABLES)["sql"] \
        == "SELECT orders.id FROM `p.retail.orders`"
    # words after a dot are never qualified
    assert tr("SELECT x.orders FROM t", tables=TABLES)["sql"] \
        == "SELECT x.orders FROM t"
    # function names are never qualified
    assert tr("orders(1)", tables=TABLES)["confidence"] == "review"
    assert "`p.retail" not in tr("orders(1)", tables=TABLES)["sql"]
    # aliases after AS are never qualified
    assert tr("SELECT 1 AS orders FROM t", tables=TABLES)["sql"] \
        == "SELECT 1 AS orders FROM t"
    # case-insensitive match
    assert tr("SELECT 1 FROM Orders", tables=TABLES)["sql"] \
        == "SELECT 1 FROM `p.retail.orders`"


def test_column_named_like_a_table_is_left_alone_outside_from():
    r = tr("(orders > 5)", tables=TABLES, columns=["orders"])
    assert r["sql"] == "(orders > 5)"
    r = tr("SELECT orders FROM orders", tables=TABLES, columns=["orders"])
    assert r["sql"] == "SELECT orders FROM `p.retail.orders`"


def test_pg_catalog_prefix_is_dropped():
    assert tr("(t > pg_catalog.now())")["sql"] \
        == "(t > CURRENT_TIMESTAMP())"


# ------------------------------------------------------------ other reviews

def test_review_constructs():
    r = tr("(a % 2) = 0")
    assert r["confidence"] == "review"
    assert any("MOD" in n for n in r["notes"])
    r = tr("(payload ->> 'k'::text) = 'v'::text")
    assert r["confidence"] == "review"
    assert "->>" in r["sql"]
    r = tr("(tags[1] = 'x'::text)")
    assert r["confidence"] == "review"
    assert any("ORDINAL" in n for n in r["notes"])
    r = tr("SELECT DISTINCT ON (a) a, b FROM t")
    assert r["confidence"] == "review"
    assert any("DISTINCT ON" in n for n in r["notes"])
    r = tr("(t AT TIME ZONE 'UTC'::text) > x")
    assert r["confidence"] == "review"
    assert any("AT TIME ZONE" in n for n in r["notes"])
    r = tr("name COLLATE \"C\" = 'x'")
    assert r["confidence"] == "review"
    r = tr("count(*) FILTER (WHERE x) > 1")
    assert r["confidence"] == "review"
    assert any("FILTER" in n for n in r["notes"])
    r = tr("ROW(a, b) = ROW(1, 2)")
    assert r["confidence"] == "review"


def test_time_functions_and_special_words():
    assert tr("d = CURRENT_DATE")["sql"] == "d = CURRENT_DATE()"
    assert tr("t < CURRENT_TIMESTAMP")["sql"] == "t < CURRENT_TIMESTAMP()"
    r = tr("t < CURRENT_TIMESTAMP(3)")
    assert r["sql"] == "t < CURRENT_TIMESTAMP()"
    assert r["confidence"] == "auto"
    assert r["notes"]
    assert tr("t < transaction_timestamp()")["sql"] \
        == "t < CURRENT_TIMESTAMP()"
    assert tr("t < LOCALTIMESTAMP")["sql"] == "t < CURRENT_DATETIME()"


def test_allowlisted_functions_are_auto():
    r = tr("coalesce(lower(a), upper(b), length(c)) = 'x'::text")
    assert r["sql"] == "coalesce(lower(a), upper(b), length(c)) = 'x'"
    assert r["confidence"] == "auto"
    r = tr("EXTRACT(year FROM d) = 2024")
    assert r["confidence"] == "auto"
    assert tr("count(*) > 1")["confidence"] == "auto"


def test_array_literal_outside_any_becomes_bracket_literal():
    r = tr("tags @> ARRAY['x'::text]")
    assert r["confidence"] == "review"
    assert "['x']" in r["sql"]
    assert any("@>" in n for n in r["notes"])


def test_exists_subquery_is_review():
    r = tr("EXISTS (SELECT 1 FROM allowed a WHERE a.id = t.id)",
           tables={"allowed": "`p.d.allowed`"})
    assert r["confidence"] == "review"
    assert "FROM `p.d.allowed` a" in r["sql"]


def test_cte_is_review_and_translated():
    r = tr("WITH x AS (SELECT id FROM orders) SELECT id FROM x",
           tables=TABLES)
    assert r["confidence"] == "review"
    assert "FROM `p.retail.orders`" in r["sql"]


# ------------------------------------------------------------ never raises

@pytest.mark.parametrize("weird", [
    "", "   ", "::", ")(", "(a", "a)", "'open", "`tick`", "@", "a ? b",
    "x::", "x::text[", "= ANY", "SELECT ;", "$1 = 2", ";", "a ~~*",
    "ARRAY[", "CAST(x AS", "'a'::", "interval", "((", "a.", ".a",
    "B'0101' = x", "x = 'a' ::",
])
def test_translate_never_raises(weird):
    r = bp.translate(weird)
    assert set(r) == {"sql", "confidence", "notes"}
    assert r["confidence"] in ("auto", "review")
    assert isinstance(r["sql"], str)
    assert all(isinstance(n, str) for n in r["notes"])


def test_unbalanced_and_empty_inputs_are_review():
    assert tr("(a")["confidence"] == "review"
    assert tr("a)")["confidence"] == "review"
    assert tr("")["confidence"] == "review"
    assert tr("'open")["confidence"] == "review"
    assert tr("'open")["sql"] == "'open"


def test_semicolon_and_whitespace_trimming():
    assert tr("  true ;  ")["sql"] == "TRUE"
    r = tr("a = 1; b = 2")
    assert r["confidence"] == "review"


def test_notes_are_deduplicated_and_readable():
    r = tr("(a ~ 'x'::text) AND (b ~ 'y'::text)")
    regex_notes = [n for n in r["notes"] if "regular expression" in n]
    assert len(regex_notes) == 1
    assert regex_notes[0].endswith(".")
    r = tr("(actor = CURRENT_USER) OR (owner = CURRENT_USER)")
    assert len(r["notes"]) == 1


def test_context_without_tables_key():
    assert bp.translate("true", {})["sql"] == "TRUE"
    assert bp.translate("true", {"tables": None})["sql"] == "TRUE"
    assert bp.translate("SELECT 1 FROM orders",
                        {"tables": {"orders": "`x.y.orders`"},
                         "columns": [{"name": "id"}]})["sql"] \
        == "SELECT 1 FROM `x.y.orders`"


def test_auto_functions_set_matches_plan():
    expected = {"coalesce", "nullif", "lower", "upper", "length", "abs",
                "greatest", "least", "trim", "ltrim", "rtrim", "concat",
                "round", "floor", "ceil", "ceiling", "mod", "left", "right",
                "replace", "starts_with", "ends_with", "cast", "extract",
                "ifnull", "count", "sum", "min", "max", "avg"}
    assert bp.AUTO_FUNCTIONS == expected


# ---------------------------------------------------------- audit additions

def test_nested_redundant_parens_collapse_to_one_layer():
    assert tr("(((a + b)))::text")["sql"] == "CAST((a + b) AS STRING)"
    assert tr("(((x)))::integer")["sql"] == "CAST(x AS INT64)"
    assert tr("((a || b))::character varying")["sql"] \
        == "CAST((a || b) AS STRING)"
    assert tr("((a || b)) ILIKE 'x%'")["sql"] \
        == "LOWER((a || b)) LIKE LOWER('x%')"
    # a group that carries real structure keeps its single layer
    assert tr("(a + b)::text")["sql"] == "CAST((a + b) AS STRING)"


def test_null_cast_becomes_explicit_cast():
    r = tr("NULL::text")
    assert r == {"sql": "CAST(NULL AS STRING)", "confidence": "auto",
                 "notes": []}


def test_combined_policy_predicate_shape():
    src = ("((region = 'eu'::text) AND (status <> 'cancelled'::text)) "
           "OR (owner = CURRENT_USER)")
    r = tr(src)
    assert r["sql"] == ("((region = 'eu') AND (status <> 'cancelled')) "
                        "OR (owner = SESSION_USER())")
    assert r["confidence"] == "auto"
    assert len(r["notes"]) == 1


def test_case_between_and_null_tests_pass_through():
    src = ("CASE WHEN qty BETWEEN 1 AND 5 THEN 'few' ELSE 'many' END = "
           "'few' AND x IS NOT NULL")
    r = tr(src)
    assert r == {"sql": src, "confidence": "auto", "notes": []}


def test_identity_note_fits_every_identity_word():
    for word in ("current_user", "session_user", "current_role"):
        r = tr(f"(x = {word})")
        assert r["confidence"] == "auto"
        assert len(r["notes"]) == 1
        note = r["notes"][0]
        assert "SESSION_USER()" in note and "email" in note
        assert word in note


# ------------------------------------------- safety review round findings

def test_double_quoted_function_names_are_functions():
    # pg_get_expr double quotes keyword-named functions; the quotes must
    # not turn them into identifiers or bypass the allowlist
    r = tr('("left"(name, 3))::text')
    assert r == {"sql": "CAST(left(name, 3) AS STRING)",
                 "confidence": "auto", "notes": []}
    r = tr("(\"left\"(name, 3) ~~* 'a%'::text)")
    assert r["sql"] == "(LOWER(left(name, 3)) LIKE LOWER('a%'))"
    assert r["confidence"] == "auto"
    r = tr('(x ~~* "right"(y, 2))')
    assert r["sql"] == "(LOWER(x) LIKE LOWER(right(y, 2)))"
    assert r["confidence"] == "auto"
    # exact pg_get_viewdef output observed on the demo source
    r = tr("\"left\"(name, 3) = 'abc'::text AND "
           "\"right\"(name, 2) ~~* 'x%'::text")
    assert r["sql"] == \
        "left(name, 3) = 'abc' AND LOWER(right(name, 2)) LIKE LOWER('x%')"
    assert r["confidence"] == "auto"
    # quoted names outside the allowlist go through the same review path
    r = tr("(\"substring\"(name, 1, 2) = 'ab'::text)")
    assert r["sql"] == "(substring(name, 1, 2) = 'ab')"
    assert r["confidence"] == "review"
    assert any("substring(...)" in n for n in r["notes"])
    r = tr('("foo"(x) = 1)')
    assert r == {"sql": "(foo(x) = 1)", "confidence": "review",
                 "notes": [("The function foo(...) is not in the allowlist "
                            "of functions that behave the same in BigQuery; "
                            "check its BigQuery equivalent by hand.")]}
    r = tr('("my func"(x) = 1)')
    assert r["sql"] == "(`my func`(x) = 1)"
    assert r["confidence"] == "review"
    r = tr("(\"current_setting\"('a'::text) = 'b'::text)")
    assert r["confidence"] == "review"
    assert any("current_setting" in n for n in r["notes"])
    assert tr("(pg_catalog.\"left\"(x, 1) = 'a'::text)")["sql"] \
        == "(left(x, 1) = 'a')"
    # a quoted column that is not followed by "(" stays an identifier
    assert tr('"left" = 1') == {"sql": "`left` = 1", "confidence": "auto",
                                "notes": []}


def test_ilike_any_over_string_array_becomes_like_any():
    # exact ruleutils form of  name ILIKE ANY (ARRAY['a%', 'b%'])
    r = tr("(name ~~* ANY (ARRAY['a%'::text, 'b%'::text]))")
    assert r == {"sql": "(LOWER(name) LIKE ANY (LOWER('a%'), LOWER('b%')))",
                 "confidence": "auto", "notes": []}
    # BigQuery NOT LIKE ANY is true when some pattern fails to match, the
    # same as PostgreSQL !~~* ANY, so the quantifier is kept
    r = tr("(name !~~* ANY (ARRAY['z%'::text]))")
    assert r == {"sql": "(LOWER(name) NOT LIKE ANY (LOWER('z%')))",
                 "confidence": "auto", "notes": []}
    r = tr("(name ~~* ALL (ARRAY['a%'::text, 'b%'::text]))")
    assert r["sql"] == "(LOWER(name) LIKE ALL (LOWER('a%'), LOWER('b%')))"
    assert r["confidence"] == "auto"
    r = tr("(name ~~* SOME (ARRAY['a%'::text]))")
    assert r["sql"] == "(LOWER(name) LIKE SOME (LOWER('a%')))"
    # the case-sensitive operator maps without LOWER()
    r = tr("(name ~~ ANY (ARRAY['q%'::text]))")
    assert r == {"sql": "(name LIKE ANY ('q%'))", "confidence": "auto",
                 "notes": []}
    assert tr("(name !~~ ALL (ARRAY['q%'::text]))")["sql"] \
        == "(name NOT LIKE ALL ('q%'))"
    # hand-written word forms
    assert tr("name ILIKE ANY (ARRAY['a%', 'b%'])")["sql"] \
        == "LOWER(name) LIKE ANY (LOWER('a%'), LOWER('b%'))"
    assert tr("name NOT ILIKE ALL (ARRAY['a%'])")["sql"] \
        == "LOWER(name) NOT LIKE ALL (LOWER('a%'))"
    assert tr("name LIKE SOME (ARRAY['a%'])")["sql"] \
        == "name LIKE SOME ('a%')"
    r = tr("((a || b)) ILIKE ANY (ARRAY['x%'])")
    assert r["sql"] == "LOWER((a || b)) LIKE ANY (LOWER('x%'))"


def test_ilike_any_over_non_literal_keeps_operator_and_is_review():
    r = tr("(name ~~* ANY (tags))")
    assert r["sql"] == "(name ~~* ANY (tags))"
    assert r["confidence"] == "review"
    assert any("LIKE ANY" in n and "UNNEST" in n for n in r["notes"])
    r = tr("(name ~~* ANY (ARRAY[col1, 'x'::text]))")
    assert r["confidence"] == "review"
    assert r["sql"].startswith("(name ~~* ANY (")
    r = tr("name NOT ILIKE ANY (pats)")
    assert r["sql"] == "name NOT ILIKE ANY (pats)"
    assert r["confidence"] == "review"
    r = tr("(name ~~ ANY (pats))")
    assert r["sql"] == "(name ~~ ANY (pats))"
    assert r["confidence"] == "review"
    assert any("LIKE ANY" in n for n in r["notes"])


def test_other_operators_before_any_all_are_review_with_advice():
    for src, op in (("(x <= ANY (ARRAY[1, 2]))", "<="),
                    ("(x > ALL (ARRAY[1, 2]))", ">"),
                    ("(x < SOME (ARRAY[1, 2]))", "<"),
                    ("(x >= ANY (ids))", ">=")):
        r = tr(src)
        assert r["confidence"] == "review", src
        assert any(f"operator {op} " in n and "UNNEST" in n
                   and f"WHERE x {op} e" in n and "LIKE ANY" in n
                   for n in r["notes"]), src
    r = tr("(x <= ANY (ARRAY[1, 2]))")
    assert r["sql"] == "(x <= ANY ([1, 2]))"
    # a quantifier with nothing recognizable before it is review too
    r = tr("ANY (ARRAY[1])")
    assert r["confidence"] == "review"
    assert r["notes"]


def test_left_and_right_are_functions_when_called():
    r = tr("(left(x, 2))::text")
    assert r == {"sql": "CAST(left(x, 2) AS STRING)", "confidence": "auto",
                 "notes": []}
    r = tr("(left(x, 2) ~~* 'p'::text)")
    assert r == {"sql": "(LOWER(left(x, 2)) LIKE LOWER('p'))",
                 "confidence": "auto", "notes": []}
    r = tr("(x ~~* right(y, 2))")
    assert r == {"sql": "(LOWER(x) LIKE LOWER(right(y, 2)))",
                 "confidence": "auto", "notes": []}
    assert tr("RIGHT(x, 1) = 'a'")["sql"] == "RIGHT(x, 1) = 'a'"
    # the join keywords are untouched
    r = tr("SELECT 1 FROM products LEFT JOIN orders ON true", tables=TABLES)
    assert r["sql"] == ("SELECT 1 FROM `p.retail.products` LEFT JOIN "
                        "`p.retail.orders` ON TRUE")
    assert r["confidence"] == "auto"
    r = tr("SELECT 1 FROM t RIGHT OUTER JOIN orders o ON (o.id = t.id)",
           tables=TABLES)
    assert r["sql"] == ("SELECT 1 FROM t RIGHT OUTER JOIN `p.retail.orders` "
                        "o ON (o.id = t.id)")


def test_bare_word_equal_to_a_table_is_not_qualified_outside_from():
    # a predicate has no FROM clause, so nothing in it is a table
    r = tr("(orders = 1)", tables=TABLES)
    assert r == {"sql": "(orders = 1)", "confidence": "auto", "notes": []}
    r = tr("(orders = 1) AND (x IN (SELECT 1 FROM orders))", tables=TABLES)
    assert r["sql"] == \
        "(orders = 1) AND (x IN (SELECT 1 FROM `p.retail.orders`))"
    assert tr("SELECT orders, 1 FROM t", tables=TABLES)["sql"] \
        == "SELECT orders, 1 FROM t"
    assert tr("SELECT 1 FROM t, orders", tables=TABLES)["sql"] \
        == "SELECT 1 FROM t, `p.retail.orders`"
    assert tr("SELECT 1 FROM t, public.orders o", tables=TABLES)["sql"] \
        == "SELECT 1 FROM t, `p.retail.orders` o"
    assert tr("SELECT 1 FROM t GROUP BY a, orders", tables=TABLES)["sql"] \
        == "SELECT 1 FROM t GROUP BY a, orders"
    assert tr("SELECT 1 FROM t WHERE (a, orders) = (1, 2)",
              tables=TABLES)["sql"] \
        == "SELECT 1 FROM t WHERE (a, orders) = (1, 2)"
    assert tr("SELECT 1 FROM t WHERE orders > 5 ORDER BY orders",
              tables=TABLES)["sql"] \
        == "SELECT 1 FROM t WHERE orders > 5 ORDER BY orders"
    # pg_get_viewdef wraps join trees in parentheses
    assert tr("SELECT 1 FROM ((t JOIN orders ON (t.id = orders.id)) "
              "JOIN customers c ON true)", tables=TABLES)["sql"] == (
        "SELECT 1 FROM ((t JOIN `p.retail.orders` ON (t.id = orders.id)) "
        "JOIN `p.retail.customers` c ON TRUE)")
    # an alias spelled like a table stays an alias
    ctx = {"allowed": "`p.d.allowed`", "a": "`p.d.a`"}
    assert tr("SELECT 1 FROM allowed a WHERE a.id = 1", tables=ctx)["sql"] \
        == "SELECT 1 FROM `p.d.allowed` a WHERE a.id = 1"


def test_string_literal_cast_to_bool_becomes_true_or_false():
    for word in ("t", "true", "yes", "on", "1", "TRUE", "Yes", "y", " t "):
        assert tr(f"(active = '{word}'::boolean)") == {
            "sql": "(active = TRUE)", "confidence": "auto", "notes": []}, word
    for word in ("f", "false", "no", "off", "0", "FALSE", "n"):
        assert tr(f"(active = '{word}'::bool)")["sql"] == "(active = FALSE)"
    r = tr("(active = 'maybe'::boolean)")
    assert r["sql"] == "(active = CAST('maybe' AS BOOL))"
    assert r["confidence"] == "review"
    assert any("'maybe'" in n for n in r["notes"])
    # a column cast is a plain CAST
    assert tr("(flag)::boolean")["sql"] == "CAST(flag AS BOOL)"


def test_cast_to_char_with_explicit_length_is_review():
    r = tr("(x)::character(3)")
    assert r["sql"] == "CAST(x AS STRING)"
    assert r["confidence"] == "review"
    assert any("truncates" in n and "character(3)" in n for n in r["notes"])
    r = tr("'abc'::char(2)")
    assert r["sql"] == "'abc'"
    assert r["confidence"] == "review"
    r = tr("(x)::character varying(20)")
    assert r["confidence"] == "review"
    # without a length there is nothing to truncate
    assert tr("(x)::character")["confidence"] == "auto"
    assert tr("'abc'::bpchar")["confidence"] == "auto"
    assert tr("(x)::varchar")["confidence"] == "auto"


def test_extract_fields():
    for field in ("year", "month", "day", "hour", "minute", "second",
                  "quarter", "isoyear", "YEAR"):
        r = tr(f"EXTRACT({field} FROM d) = 1")
        assert r == {"sql": f"EXTRACT({field} FROM d) = 1",
                     "confidence": "auto", "notes": []}, field
    # PostgreSQL week is the ISO week; BigQuery WEEK is Sunday-based
    r = tr("EXTRACT(week FROM d) = 3")
    assert r["sql"] == "EXTRACT(ISOWEEK FROM d) = 3"
    assert r["confidence"] == "auto"
    assert any("ISOWEEK" in n for n in r["notes"])
    for field, equiv in (("epoch", "UNIX_SECONDS"), ("dow", "DAYOFWEEK"),
                         ("doy", "DAYOFYEAR"), ("isodow", "DAYOFWEEK")):
        r = tr(f"(EXTRACT({field} FROM d) = (1)::numeric)")
        assert r["sql"] == f"(EXTRACT({field} FROM d) = CAST(1 AS NUMERIC))"
        assert r["confidence"] == "review", field
        assert any(equiv in n for n in r["notes"]), field
    assert any("1-based" in n for n in tr("EXTRACT(dow FROM d) = 1")["notes"])
    for field in ("century", "decade", "millennium", "microseconds",
                  "milliseconds", "timezone", "julian", "EPOCH", "nonsense"):
        r = tr(f"EXTRACT({field} FROM d) = 1")
        assert r["sql"] == f"EXTRACT({field} FROM d) = 1"
        assert r["confidence"] == "review", field
    # the field check applies only inside extract(...)
    assert tr("(epoch = 1)")["confidence"] == "auto"
    assert tr("(dow > week)")["confidence"] == "auto"


# ------------------------------------------ review round two (live shapes)
# Inputs quoted from EXPLAIN VERBOSE / format_type on the demo source are
# marked "live"; they pin real pg_get_expr forms, not hand-written SQL.

COLS_TYPED = [{"name": "ordered_at", "bq_type": "TIMESTAMP"},
              {"name": "created_at", "bq_type": "DATETIME"},
              {"name": "d", "bq_type": "DATE"},
              {"name": "amount", "bq_type": "INT64"},
              {"name": "price", "bq_type": "NUMERIC"}]


def test_temporal_family_mismatch_is_review_when_types_are_known():
    # a plain timestamp column (DATETIME) against now() (TIMESTAMP)
    r = tr("(created_at > now())", columns=COLS_TYPED)
    assert r["sql"] == "(created_at > CURRENT_TIMESTAMP())"
    assert r["confidence"] == "review"
    assert any("DATETIME" in n and "TIMESTAMP(created_at" in n
               and "CURRENT_DATETIME()" in n for n in r["notes"])
    # live: a timestamptz column against CURRENT_DATE and a date literal
    r = tr("(orders.ordered_at > CURRENT_DATE)", columns=COLS_TYPED)
    assert r["sql"] == "(orders.ordered_at > CURRENT_DATE())"
    assert r["confidence"] == "review"
    assert any("DATE(orders.ordered_at" in n for n in r["notes"])
    r = tr("(orders.ordered_at > '2024-01-01'::date)", columns=COLS_TYPED)
    assert r["sql"] == "(orders.ordered_at > DATE '2024-01-01')"
    assert r["confidence"] == "review"
    # matching families stay auto with no note
    assert tr("(ordered_at > now())", columns=COLS_TYPED) == {
        "sql": "(ordered_at > CURRENT_TIMESTAMP())", "confidence": "auto",
        "notes": []}
    assert tr("(created_at > LOCALTIMESTAMP)", columns=COLS_TYPED) == {
        "sql": "(created_at > CURRENT_DATETIME())", "confidence": "auto",
        "notes": []}
    assert tr("(d > CURRENT_DATE)", columns=COLS_TYPED)["notes"] == []
    assert tr("(ordered_at > (now() - '90 days'::interval))",
              columns=COLS_TYPED) == {
        "sql": "(ordered_at > (CURRENT_TIMESTAMP() - INTERVAL 90 DAY))",
        "confidence": "auto", "notes": []}
    # BigQuery coerces DATE to DATETIME, so that pair is fine
    assert tr("(created_at >= '2024-01-01'::date)", columns=COLS_TYPED) == {
        "sql": "(created_at >= DATE '2024-01-01')", "confidence": "auto",
        "notes": []}
    # a DATE minus an interval is a DATETIME in BigQuery
    r = tr("(ordered_at > (CURRENT_DATE - '7 days'::interval))",
           columns=COLS_TYPED)
    assert r["confidence"] == "review"
    assert any("mixes TIMESTAMP and DATETIME" in n for n in r["notes"])
    # every comparison operator is checked, on either side
    for op in ("=", "<>", "!=", "<", ">", "<=", ">="):
        assert tr(f"(now() {op} created_at)",
                  columns=COLS_TYPED)["confidence"] == "review", op


def test_temporal_cast_atoms_are_checked_without_column_types():
    # live: (ordered_at::timestamp > now() - interval '90 days')
    r = tr("((orders.ordered_at)::timestamp without time zone > "
           "(now() - '90 days'::interval))")
    assert r["sql"] == ("(CAST(orders.ordered_at AS DATETIME) > "
                        "(CURRENT_TIMESTAMP() - INTERVAL 90 DAY))")
    assert r["confidence"] == "review"
    assert any("mixes DATETIME and TIMESTAMP" in n for n in r["notes"])
    r = tr("(t >= '2024-01-01 10:00:00'::timestamp)",
           columns=[{"name": "t", "bq_type": "TIMESTAMP"}])
    assert r["confidence"] == "review"
    assert any("DATETIME(t, zone)" in n for n in r["notes"])
    # live: a typmod cast back to the column's own family is exact
    assert tr("((orders.ordered_at)::timestamp(0) with time zone > now())",
              columns=COLS_TYPED)["notes"] == []


def test_temporal_comparison_with_untyped_column_is_auto_with_note():
    r = tr("(created_at > now())")
    assert r["sql"] == "(created_at > CURRENT_TIMESTAMP())"
    assert r["confidence"] == "auto"
    assert len(r["notes"]) == 1
    assert "created_at" in r["notes"][0] and "TIMESTAMP" in r["notes"][0]
    assert "TIMESTAMP(created_at, zone)" in r["notes"][0]
    # inventory column dicts carry the type through bq_types.map_type
    inv = [{"name": "created_at",
            "data_type": "timestamp without time zone",
            "udt_name": "timestamp"}]
    assert tr("(created_at > now())", columns=inv)["confidence"] == "review"
    inv = [{"name": "created_at", "data_type": "timestamp with time zone",
            "udt_name": "timestamptz"}]
    assert tr("(created_at > now())", columns=inv) == {
        "sql": "(created_at > CURRENT_TIMESTAMP())", "confidence": "auto",
        "notes": []}
    # a string literal against a date column is a literal coercion
    assert tr("(d = 'x')", columns=COLS_TYPED)["notes"] == []
    # a column declared with two types counts as unknown
    two = [{"name": "x", "bq_type": "DATE"}, {"name": "x", "bq_type": "TIMESTAMP"}]
    r = tr("(x > CURRENT_DATE)", columns=two)
    assert r["confidence"] == "auto" and len(r["notes"]) == 1
    # plain string column names still work as context
    assert tr("(x > CURRENT_DATE)", columns=["x"])["confidence"] == "auto"


def test_case_expression_as_ilike_operand():
    # live: Filter of WHERE CASE WHEN status='x' THEN 'a' ELSE 'b' END ILIKE 'A%'
    r = tr("(CASE WHEN (status = 'x'::text) THEN 'a'::text ELSE 'b'::text "
           "END ~~* 'A%'::text)")
    assert r == {"sql": "(LOWER(CASE WHEN (status = 'x') THEN 'a' ELSE 'b' "
                        "END) LIKE LOWER('A%'))",
                 "confidence": "auto", "notes": []}
    r = tr("(name ~~* CASE WHEN (x = 1) THEN 'a'::text ELSE 'b'::text END)")
    assert r == {"sql": "(LOWER(name) LIKE LOWER(CASE WHEN (x = 1) THEN 'a' "
                        "ELSE 'b' END))",
                 "confidence": "auto", "notes": []}
    assert tr("CASE WHEN x THEN 'a' ELSE 'b' END ILIKE 'A%'")["sql"] \
        == "LOWER(CASE WHEN x THEN 'a' ELSE 'b' END) LIKE LOWER('A%')"
    assert tr("name NOT ILIKE CASE WHEN x THEN 'a' ELSE 'b' END")["sql"] \
        == "LOWER(name) NOT LIKE LOWER(CASE WHEN x THEN 'a' ELSE 'b' END)"
    r = tr("(CASE WHEN a THEN CASE WHEN b THEN 'x' ELSE 'y' END ELSE 'z' "
           "END ~~* 'x'::text)")
    assert r["sql"] == ("(LOWER(CASE WHEN a THEN CASE WHEN b THEN 'x' ELSE "
                        "'y' END ELSE 'z' END) LIKE LOWER('x'))")
    assert r["confidence"] == "auto"
    assert tr("CASE WHEN x THEN 1 ELSE 0 END::numeric")["sql"] \
        == "CAST(CASE WHEN x THEN 1 ELSE 0 END AS NUMERIC)"
    # an END with no CASE, or a CASE with no END, is a missing operand
    assert tr("(END ~~* 'a')")["confidence"] == "review"
    assert tr("(name ~~* CASE WHEN x THEN 'a')")["confidence"] == "review"


def test_typmod_on_first_word_of_multi_word_type():
    # live: format_type prints timestamp(0) with time zone
    r = tr("((orders.ordered_at)::timestamp(0) with time zone > now())")
    assert r == {"sql": "(CAST(orders.ordered_at AS TIMESTAMP) > "
                        "CURRENT_TIMESTAMP())",
                 "confidence": "auto", "notes": []}
    assert tr("(t)::time(3) without time zone") == {
        "sql": "CAST(t AS TIME)", "confidence": "auto", "notes": []}
    r = tr("'2024-01-01 10:00:00+00'::timestamp(0) with time zone")
    assert r == {"sql": "TIMESTAMP '2024-01-01 10:00:00+00'",
                 "confidence": "auto", "notes": []}
    assert tr("(x)::timestamp(6) without time zone")["sql"] \
        == "CAST(x AS DATETIME)"
    assert tr("(x)::character varying(20)")["sql"] == "CAST(x AS STRING)"


def test_bare_set_operators_get_distinct():
    for op in ("UNION", "INTERSECT", "EXCEPT"):
        r = tr(f"SELECT id FROM orders {op} SELECT id FROM customers",
               tables=TABLES)
        assert r["sql"] == (f"SELECT id FROM `p.retail.orders` {op} DISTINCT "
                            "SELECT id FROM `p.retail.customers`")
        assert r["confidence"] == "auto"
        assert any(f"{op} DISTINCT" in n for n in r["notes"])
    r = tr("SELECT a FROM orders UNION ALL SELECT a FROM customers UNION "
           "SELECT a FROM products", tables=TABLES)
    assert r["sql"] == ("SELECT a FROM `p.retail.orders` UNION ALL SELECT a "
                        "FROM `p.retail.customers` UNION DISTINCT SELECT a "
                        "FROM `p.retail.products`")
    assert r["confidence"] == "auto"
    assert tr("SELECT 1 union distinct SELECT 2")["sql"] \
        == "SELECT 1 union distinct SELECT 2"
    assert tr("SELECT 1 union SELECT 2")["sql"] == "SELECT 1 union distinct SELECT 2"
    # ALL after a set operator is not a quantifier, even before a branch
    # in parentheses
    r = tr("SELECT a FROM orders UNION ALL (SELECT a FROM customers ORDER "
           "BY a LIMIT 1)", tables=TABLES)
    assert r["sql"] == ("SELECT a FROM `p.retail.orders` UNION ALL (SELECT a "
                        "FROM `p.retail.customers` ORDER BY a LIMIT 1)")
    assert not any("quantified" in n for n in r["notes"])


def test_numeric_scale_cast_rounds():
    # live: Filter of WHERE (id::numeric * 1.1)::numeric(10,2) > 1
    r = tr("((((orders.id)::numeric * 1.1))::numeric(10,2) > '1'::numeric)")
    assert r["sql"] == ("(ROUND(CAST((CAST(orders.id AS NUMERIC) * 1.1) AS "
                        "NUMERIC), 2) > CAST('1' AS NUMERIC))")
    assert r["confidence"] == "auto"
    assert any("ROUND" in n and "numeric(10,2)" in n for n in r["notes"])
    assert tr("((price * 1.1))::numeric(10,2)")["sql"] \
        == "ROUND(CAST((price * 1.1) AS NUMERIC), 2)"
    # an operand that is already NUMERIC is rounded without a second cast
    assert tr("((x)::numeric)::numeric(12, 3)")["sql"] \
        == "ROUND(CAST(x AS NUMERIC), 3)"
    assert tr("(x)::numeric(10)")["sql"] == "CAST(x AS NUMERIC)"
    assert tr("(x)::numeric")["notes"] == []
    assert tr("(x)::numeric(50,12)")["confidence"] == "review"


def test_integer_division_is_review_unless_an_operand_is_non_integer():
    r = tr("((amount / 100) > 10)")
    assert r["sql"] == "((amount / 100) > 10)"
    assert r["confidence"] == "review"
    assert any("DIV(a, b)" in n for n in r["notes"])
    # live
    assert tr("((orders.id / orders.customer_id) > 1)")["confidence"] \
        == "review"
    # a known non-integer operand keeps auto
    assert tr("((amount / 100.0) > 10)")["confidence"] == "auto"
    assert tr("((amount / (100)::numeric) > 10)")["confidence"] == "auto"
    assert tr("((price / 100) > 10)", columns=COLS_TYPED)["confidence"] \
        == "auto"
    assert tr("((amount / 100) > 10)", columns=COLS_TYPED)["confidence"] \
        == "review"
    assert tr("((amount / 100) > 10)",
              columns=[{"name": "amount", "bq_type": "FLOAT64"}])[
                  "confidence"] == "auto"
    assert tr("((a * b) / 2.0)")["confidence"] == "auto"


def test_json_casts():
    assert tr("('{}'::text)::jsonb") == {"sql": "PARSE_JSON('{}')",
                                         "confidence": "auto", "notes": []}
    assert tr("'{\"a\": 1}'::json")["sql"] == "PARSE_JSON('{\"a\": 1}')"
    r = tr("(payload)::jsonb")
    assert r["sql"] == "CAST(payload AS JSON)"
    assert r["confidence"] == "review"
    assert any("PARSE_JSON" in n and "TO_JSON" in n for n in r["notes"])
    # a column known to be STRING parses, one known to be JSON drops the cast
    assert tr("(payload)::jsonb",
              columns=[{"name": "payload", "bq_type": "STRING"}])["sql"] \
        == "PARSE_JSON(payload)"
    assert tr("(payload)::jsonb",
              columns=[{"name": "payload", "bq_type": "JSON"}]) == {
        "sql": "payload", "confidence": "auto", "notes": []}
    assert tr("CAST(x AS jsonb)")["confidence"] == "review"


def test_bytea_hex_literal_becomes_from_hex():
    # live: Filter of WHERE status::bytea = '\x6575'::bytea
    r = tr(r"((orders.status)::bytea = '\x6575'::bytea)")
    assert r == {"sql": "(CAST(orders.status AS BYTES) = FROM_HEX('6575'))",
                 "confidence": "auto", "notes": []}
    assert tr(r"(x = '\x'::bytea)")["sql"] == "(x = FROM_HEX(''))"
    assert tr(r"(x = '\xDEADbeef'::bytea)")["sql"] \
        == "(x = FROM_HEX('DEADbeef'))"
    r = tr("(x = 'abc'::bytea)")
    assert r["sql"] == "(x = CAST('abc' AS BYTES))"
    assert r["confidence"] == "review"
    assert any("hex" in n for n in r["notes"])
    assert tr(r"(x = '\x123'::bytea)")["confidence"] == "review"
    assert tr("(col)::bytea") == {"sql": "CAST(col AS BYTES)",
                                  "confidence": "auto", "notes": []}


def test_quoted_table_names_in_from_are_qualified():
    assert tr('SELECT 1 FROM "Orders" o', tables=TABLES)["sql"] \
        == "SELECT 1 FROM `p.retail.orders` o"
    assert tr('SELECT 1 FROM "public"."orders"', tables=TABLES)["sql"] \
        == "SELECT 1 FROM `p.retail.orders`"
    assert tr('SELECT 1 FROM public."Orders" o', tables=TABLES)["sql"] \
        == "SELECT 1 FROM `p.retail.orders` o"
    assert tr('SELECT 1 FROM "public".orders', tables=TABLES)["sql"] \
        == "SELECT 1 FROM `p.retail.orders`"
    both = dict(TABLES, t="`p.d.t`")
    assert tr('SELECT 1 FROM t JOIN "customers" c ON c.id = t.id',
              tables=both)["sql"] \
        == "SELECT 1 FROM `p.d.t` JOIN `p.retail.customers` c ON c.id = t.id"
    # an exact key wins over the case-insensitive fallback
    mixed = {"Orders": "`p.retail.Orders`", "orders": "`p.retail.orders`"}
    assert tr('SELECT 1 FROM "Orders"', tables=mixed)["sql"] \
        == "SELECT 1 FROM `p.retail.Orders`"
    # quoted names outside table position stay identifiers
    assert tr('SELECT "orders" FROM t', tables=both)["sql"] \
        == "SELECT `orders` FROM `p.d.t`"
    assert tr('"orders" = 1', tables=TABLES)["sql"] == "`orders` = 1"
    assert tr('SELECT 1 FROM t WHERE "orders" > 1', tables=both)["sql"] \
        == "SELECT 1 FROM `p.d.t` WHERE `orders` > 1"
    r = tr('SELECT 1 FROM "Archive"."orders"', tables=TABLES)
    assert r["sql"] == "SELECT 1 FROM `Archive`.`orders`"
    assert r["confidence"] == "review"


def test_from_inside_distinct_from_and_function_syntax_is_not_a_table_list():
    tables = dict(TABLES, region="`p.retail.region`")
    # live: (orders.region IS DISTINCT FROM orders.status)
    assert tr("(a IS DISTINCT FROM orders)", tables=tables) == {
        "sql": "(a IS DISTINCT FROM orders)", "confidence": "auto",
        "notes": []}
    # live: EXTRACT(year FROM orders.ordered_at) = '2024'::numeric
    r = tr("(EXTRACT(year FROM region) = '2024'::numeric)", tables=tables)
    assert r["sql"] == "(EXTRACT(year FROM region) = CAST('2024' AS NUMERIC))"
    assert r["confidence"] == "auto"
    r = tr("SELECT 1 FROM customers JOIN region r ON region = r.id",
           tables=tables)
    assert r["sql"] == ("SELECT 1 FROM `p.retail.customers` JOIN "
                        "`p.retail.region` r ON region = r.id")
    assert r["confidence"] == "auto"
    # a real FROM in the same statement still qualifies its tables
    r = tr("SELECT 1 FROM orders WHERE a IS DISTINCT FROM region",
           tables=tables)
    assert r["sql"] == \
        "SELECT 1 FROM `p.retail.orders` WHERE a IS DISTINCT FROM region"
    assert r["confidence"] == "auto"
    r = tr("SELECT EXTRACT(year FROM region) FROM orders", tables=tables)
    assert r["sql"] == "SELECT EXTRACT(year FROM region) FROM `p.retail.orders`"
    # live: TRIM(BOTH 'x'::text FROM orders.status) is PostgreSQL syntax
    r = tr("(TRIM(BOTH 'x'::text FROM region) = 'y'::text)", tables=tables)
    assert r["sql"] == "(TRIM(BOTH 'x' FROM region) = 'y')"
    assert r["confidence"] == "review"
    assert any("TRIM(y, x)" in n for n in r["notes"])


def test_null_semantics_notes_for_concat_greatest_least():
    # live: concat(orders.status, ' ', orders.region) = 'x'::text
    r = tr("(concat(orders.status, ' ', orders.region) = 'x'::text)")
    assert r["sql"] == "(concat(orders.status, ' ', orders.region) = 'x')"
    assert r["confidence"] == "auto"
    assert any("IFNULL" in n for n in r["notes"])
    # live: GREATEST(orders.id, orders.customer_id) > 1
    r = tr("(GREATEST(orders.id, orders.customer_id) > 1)")
    assert r["sql"] == "(GREATEST(orders.id, orders.customer_id) > 1)"
    assert r["confidence"] == "auto"
    assert any("UNNEST" in n and "MAX" in n for n in r["notes"])
    assert any("MIN" in n for n in tr("least(a, b)")["notes"])
    assert tr("coalesce(a, b)")["notes"] == []


def test_unmapped_table_in_from_is_review_only_with_a_table_map():
    r = tr("SELECT 1 FROM archive.orders a", tables=TABLES)
    assert r["sql"] == "SELECT 1 FROM archive.orders a"
    assert r["confidence"] == "review"
    assert [n for n in r["notes"] if "archive.orders" in n]
    assert not [n for n in r["notes"] if "table a " in n]
    r = tr("SELECT 1 FROM t LEFT JOIN orders ON true", tables=TABLES)
    assert r["confidence"] == "review"
    assert any("table t " in n for n in r["notes"])
    # pg_get_viewdef wraps join trees: the alias after "(t a" is an alias
    r = tr("SELECT 1 FROM (orders o JOIN customers c ON (c.id = o.id))",
           tables=TABLES)
    assert r == {"sql": "SELECT 1 FROM (`p.retail.orders` o JOIN "
                        "`p.retail.customers` c ON (c.id = o.id))",
                 "confidence": "auto", "notes": []}
    # predicate-only callers pass no map and get no note
    assert tr("SELECT 1 FROM archive.orders a") == {
        "sql": "SELECT 1 FROM archive.orders a", "confidence": "auto",
        "notes": []}
    # CTE names and subquery aliases are not tables
    r = tr("WITH recent AS (SELECT id FROM orders) SELECT id FROM recent",
           tables=TABLES)
    assert "FROM `p.retail.orders`" in r["sql"]
    assert not any("inventory" in n for n in r["notes"])
    r = tr("WITH recent(id) AS (SELECT id FROM orders) SELECT r.id FROM "
           "recent r", tables=TABLES)
    assert not any("inventory" in n for n in r["notes"])
    r = tr("SELECT x.a FROM (SELECT a FROM orders) x", tables=TABLES)
    assert not any("inventory" in n for n in r["notes"])
    assert any("allowed in a view" in n for n in r["notes"])


def test_hand_written_ilike_and_cast_shapes():
    assert tr("name ILIKE x || 'B%'")["sql"] \
        == "LOWER(name) LIKE LOWER(x || 'B%')"
    assert tr("a || b ILIKE 'x%'")["sql"] == "LOWER(a || b) LIKE LOWER('x%')"
    assert tr("a || b || c ILIKE 'x%' || d")["sql"] \
        == "LOWER(a || b || c) LIKE LOWER('x%' || d)"
    assert tr("lower (x)::text")["sql"] == "CAST(lower (x) AS STRING)"
    assert tr("(t.current_user = 1)") == {"sql": "(t.current_user = 1)",
                                          "confidence": "auto", "notes": []}
    assert tr("(t.true = 1)")["sql"] == "(t.true = 1)"
    assert tr("(t.current_date > 1)")["sql"] == "(t.current_date > 1)"
    # a schema-qualified function still goes through the allowlist
    r = tr("(myschema.my_func(x) = 1)")
    assert r["confidence"] == "review"
    assert any("my_func" in n for n in r["notes"])


def test_postgres_only_spellings_are_review():
    r = tr("qty BETWEEN SYMMETRIC 5 AND 1")
    assert r["sql"] == "qty BETWEEN SYMMETRIC 5 AND 1"
    assert r["confidence"] == "review"
    assert any("LEAST" in n for n in r["notes"])
    assert tr("qty BETWEEN 1 AND 5")["confidence"] == "auto"
    r = tr("x ISNULL")
    assert r["confidence"] == "review"
    assert any("IS NULL" in n for n in r["notes"])
    assert any("IS NOT NULL" in n for n in tr("x NOTNULL")["notes"])
    r = tr("SELECT 1 FROM ONLY orders", tables=TABLES)
    assert r["sql"] == "SELECT 1 FROM ONLY `p.retail.orders`"
    assert r["confidence"] == "review"
    assert any("ONLY" in n for n in r["notes"])


def test_interval_field_lists_from_format_type():
    # live: format_type prints interval day, interval day to second(3), ...
    assert tr("'1 day'::interval day") == {"sql": "INTERVAL 1 DAY",
                                            "confidence": "auto", "notes": []}
    assert tr("'2 hours'::interval hour")["sql"] == "INTERVAL 2 HOUR"
    assert tr("'1 second'::interval(3)")["sql"] == "INTERVAL 1 SECOND"
    assert tr("'1 day'::interval day to second(3)")["sql"] == "INTERVAL 1 DAY"
    assert tr("'1 day'::interval hour to minute")["sql"] == "INTERVAL 1 DAY"
    assert tr("'2 weeks'::interval day")["sql"] == "INTERVAL 2 WEEK"
    assert tr("(x > (now() - '1 day'::interval day))",
              columns=[{"name": "x", "bq_type": "TIMESTAMP"}]) == {
        "sql": "(x > (CURRENT_TIMESTAMP() - INTERVAL 1 DAY))",
        "confidence": "auto", "notes": []}
    # a field list that truncates the literal is review ('90 minutes'::
    # interval hour is 1 hour on the source)
    r = tr("'90 minutes'::interval hour")
    assert r["confidence"] == "review"
    assert r["sql"] == "'90 minutes'::interval hour"
    assert any("whole hours" in n for n in r["notes"])
    assert tr("'1 day'::interval year to month")["confidence"] == "review"
    assert tr("'1 day'::interval AND x")["sql"] == "INTERVAL 1 DAY AND x"


def test_btrim_maps_to_trim():
    assert tr("(btrim(status) = 'x'::text)") == {
        "sql": "(trim(status) = 'x')", "confidence": "auto", "notes": []}
    assert tr("(BTRIM(status, 'x'::text) = 'y'::text)")["sql"] \
        == "(TRIM(status, 'x') = 'y')"
