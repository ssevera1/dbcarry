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
    assert r["confidence"] == "review"
    assert "current_setting('app.tenant'" in r["sql"]
    assert r["sql"].startswith("(tenant_id = ")
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
    assert r["confidence"] == "review"
    assert " ~ " in r["sql"] and "'^a'" in r["sql"] and "name" in r["sql"]
    assert any("regular expression" in n for n in r["notes"])


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
    r = tr(src, tables=TABLES)
    assert r["sql"] == (
        "SELECT o.id, c.email, o.status, o.ordered_at FROM "
        "(`p.retail.orders` o JOIN `p.retail.customers` c "
        "ON ((c.id = o.customer_id))) WHERE "
        "(o.ordered_at > (CURRENT_TIMESTAMP() - INTERVAL 90 DAY))")
    assert r["confidence"] == "auto"
    assert r["notes"] == []


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
