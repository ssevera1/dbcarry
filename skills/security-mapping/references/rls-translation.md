# Predicate translation (spec section 8)

`bq_predicate.translate(expr, context) -> {"sql", "confidence",
"notes"}` rewrites PostgreSQL expressions as `pg_get_expr` and
`pg_get_viewdef` print them (fully parenthesized, literals with explicit
`::type` casts, keyword-named functions double quoted, ILIKE spelled
`~~*`). It is rule-based text rewriting over a token stream,
conservative by design: every construct it recognizes is rewritten in
place, everything else is passed through and the result is marked
`review` with a note that names the construct. It never raises; the
fallback is the original text at `review`. The same function serves
row-level security predicates (this file) and view bodies (the schema
phase). What this file says BigQuery accepts or returns comes from its
documentation and is NOT LIVE-TESTED.

`context` is `{"tables": {bare and qualified name: backticked BigQuery
name}, "columns": [inventory column dicts of the table at hand]}`. The
planner builds it from every table, view, and materialized view of the
migration; with column types present the translator also checks that
date, datetime, and timestamp comparisons and integer division keep
their meaning.

Every input and output below is copied from `tests/test_bq_predicate.py`;
the demo rows are the exact `pg_get_expr` output observed on the demo
source.

## Auto rules, one worked example each

| Rule | Input | Output | Confidence |
|---|---|---|---|
| Identity words `current_user`, `session_user`, `current_role` become `SESSION_USER()` | `(actor = CURRENT_USER)` (demo policy `audit_self`) | `(actor = SESSION_USER())` | auto, one note (the identity caveat below) |
| Same, with the cast `pg_get_expr` adds | `(actor = (CURRENT_USER)::text)` | `(actor = SESSION_USER())` | auto |
| `::type` cast becomes `CAST(x AS <mapped type>)`; redundant parentheses around the atom are dropped | `(amount > (100)::numeric)` | `(amount > CAST(100 AS NUMERIC))` | auto |
| Cast of an expression keeps its own parentheses | `((a + b))::double precision` | `CAST((a + b) AS FLOAT64)` | auto |
| A string literal cast to text or varchar drops the cast | `(region = 'eu'::text)` (demo policy `orders_region_eu`) | `(region = 'eu')` | auto, no notes |
| `now()` becomes `CURRENT_TIMESTAMP()`; an interval literal becomes `INTERVAL N UNIT` | `(ordered_at > (now() - '90 days'::interval))` (demo view `recent_orders`) | `(ordered_at > (CURRENT_TIMESTAMP() - INTERVAL 90 DAY))` | auto |
| `CURRENT_DATE` and `CURRENT_TIMESTAMP` gain parentheses | `d = CURRENT_DATE` | `d = CURRENT_DATE()` | auto |
| A string literal cast to date becomes a typed literal | `(created_at >= '2024-01-01'::date)` | `(created_at >= DATE '2024-01-01')` | auto |
| Same for timestamps (with time zone to TIMESTAMP, without to DATETIME) | `(t >= '2024-01-01 10:00:00+00'::timestamp with time zone)` | `(t >= TIMESTAMP '2024-01-01 10:00:00+00')` | auto |
| ILIKE (`~~*`) becomes `LOWER(a) LIKE LOWER(b)` | `(name ~~* 'a%'::text)` | `(LOWER(name) LIKE LOWER('a%'))` | auto |
| `= ANY (ARRAY[...])` becomes `IN (...)` | `(status = ANY (ARRAY['a'::text, 'b'::text]))` | `(status IN ('a', 'b'))` | auto |
| `<> ALL (ARRAY[...])` becomes `NOT IN (...)` | `(status <> ALL (ARRAY['cancelled'::text, 'refunded'::text]))` | `(status NOT IN ('cancelled', 'refunded'))` | auto |
| Double-quoted identifiers become backticks | `"quoted col" = 1` | `` `quoted col` = 1 `` | auto, no notes |
| Bare table names in FROM or JOIN position that exist in the context become the qualified name | `SELECT o.id, c.email FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.ordered_at > (now() - '90 days'::interval)` with tables `{"orders": "`p.retail.orders`", "customers": "`p.retail.customers`", ...}` | ``SELECT o.id, c.email FROM `p.retail.orders` o JOIN `p.retail.customers` c ON c.id = o.customer_id WHERE o.ordered_at > (CURRENT_TIMESTAMP() - INTERVAL 90 DAY)`` | auto |
| A word that matches a table name outside FROM position is left alone (a predicate has no FROM clause) | `(orders = 1)` with the same tables | `(orders = 1)` | auto, no notes |
| `true` and `false` are always upper-cased; other keywords keep their case | `true` (demo policies `orders_all_rw`, `audit_all_rw`) | `TRUE` | auto, no notes |
| Allowlisted functions pass through (`AUTO_FUNCTIONS`: coalesce, nullif, lower, upper, length, abs, greatest, least, trim, ltrim, rtrim, concat, round, floor, ceil, ceiling, mod, left, right, replace, starts_with, ends_with, cast, extract, ifnull, count, sum, min, max, avg) | `coalesce(lower(a), upper(b), length(c)) = 'x'::text` | `coalesce(lower(a), upper(b), length(c)) = 'x'` | auto |

Some auto results still carry a note the reviewer should read: a
`concat`, `greatest`, or `least` call (NULL handling differs), an
`EXTRACT(week ...)` rewritten to `ISOWEEK`, a temporal comparison whose
column type the context did not supply, and `numeric(p,s)` casts
rewritten with `ROUND`.

## Review triggers, one worked example each

| Trigger | Input | Output | Note says |
|---|---|---|---|
| `current_setting(...)` (no session variables on BigQuery) | `(tenant_id = (current_setting('app.tenant'::text))::integer)` | `(tenant_id = CAST(current_setting('app.tenant') AS INT64))` | `current_setting` cannot be evaluated; carry the value through `SESSION_USER()` and a mapping table, or drop the condition |
| A function outside the allowlist | `some_func(x) = 1` | `some_func(x) = 1` | `The function some_func(...) is not in the allowlist of functions that behave the same in BigQuery; check its BigQuery equivalent by hand.` |
| A subquery (tables inside it are still qualified) | `(id IN (SELECT id FROM allowed))` with tables `{"allowed": "`p.d.allowed`"}` | ``(id IN (SELECT id FROM `p.d.allowed`))`` | subquery: BigQuery row access policies allow only a limited subquery form; review |
| A regular-expression operator (`~`, `~*`, `!~`, `!~*`, `SIMILAR TO`) | `(name ~ '^a'::text)` | `(name ~ '^a')` | regular expression: write `REGEXP_CONTAINS` by hand |
| An unknown or array cast | `(tags)::text[]` | unchanged text | array cast has no CAST form |
| Anything the tokenizer cannot account for (unbalanced parentheses, an unterminated quote, an empty expression, two statements) | `'open` | `'open` | unterminated literal |
| Other constructs with advice in the note: `%` (write `MOD`), `->>` and `->` (JSON_VALUE, JSON_QUERY), `@>` (EXISTS over UNNEST), array subscripts (`ORDINAL`), `DISTINCT ON`, `AT TIME ZONE`, `COLLATE`, aggregate `FILTER`, `ROW(...)`, `E'...'` escape strings, dollar quoting, `BETWEEN SYMMETRIC`, `ISNULL`, `FROM ONLY`, integer division with two integer operands (write `DIV`) | `((amount / 100) > 10)` | `((amount / 100) > 10)` | `DIV(a, b)` for integer operands |

## A review result is a partial translation

Everything the translator recognizes is rewritten even when the result
is `review`; only the construct that triggered the note is left in
PostgreSQL form:

| Input | Output | Confidence |
|---|---|---|
| `(a ~ 'x'::text) AND (b = 'y'::text) AND (c = CURRENT_USER)` | `(a ~ 'x') AND (b = 'y') AND (c = SESSION_USER())` | review (two notes: the regex operator and the identity caveat) |

Notes are deduplicated (two regex operators produce one note) and end
with a period.

## The combined-predicate rule for several policies

The planner translates each source policy's USING clause once, then
combines the translated pieces per (table, role) with
`combine_predicates(permissive, restrictive)`: `(p1) OR (p2) ...` for
the permissive ones, then `AND (r)` per restrictive one; a single
permissive with no restrictive stands as written. The PostgreSQL count
query behind the probes combines the source predicates the same way.

Fixture from `tests/test_bq_security.py`, table `orders` with RLS:

| Source policy | Roles | Permissive | USING |
|---|---|---|---|
| `eu` | reporting | yes | `(region = 'eu'::text)` |
| `paid` | reporting | yes | `(status = 'paid'::text)` |
| `not_void` | PUBLIC | no (restrictive) | `(status <> 'void'::text)` |
| `rw_all` | app_rw (command ALL) | yes | `true` |

Result: `rls_reporting` gets `((region = 'eu') OR (status = 'paid'))
AND (status <> 'void')`; `rls_app_rw` gets `(TRUE) AND (status <>
'void')`; `app_ro`, reached only by the restrictive policy, gets no
policy at all (INFO `rls_denies_role`), because a restrictive policy
alone allows nothing on PostgreSQL either.

The demo has one permissive policy per (table, role), so its filters
stand as written: `(region = 'eu')`, `TRUE`, `(actor = SESSION_USER())`.

## The SESSION_USER() identity caveat

The translator's note, verbatim (with the source word filled in):

> current_user became SESSION_USER(). PostgreSQL current_user is a
> role name and BigQuery SESSION_USER() is the caller's email address,
> so the compared column must hold Google identities on the target, or
> the predicate needs a mapping table from role names to email
> addresses.

The planner adds INFO `identity_predicate` per such policy, collects
the note under `identity_notes` in the plan and in
`70-identity-notes.md`, and the probes report the BigQuery count for
that table without comparing it with the source (the source count
depends on a role name, the target count on an email). On the demo,
`audit_log.actor` holds role-style names, so `app_ro` and `reporting`
see zero rows on the target; that is the correct translation of an
untranslatable comparison, and the plan says so rather than hiding it.
The fix belongs to the operator: load Google identities into the
column, or resolve the policy to a lookup against a mapping table on
the target.

## What a review result means for the sql-translator agent

Input: `artifacts/translation-review.json`, whose `policies` map is
keyed `schema.table/policy` and holds `source_sql` (the USING text as
the inventory recorded it), `auto_sql` (the partial translation above;
identical to `source_sql` only when the tokenizer failed), `notes` (the
contract: each names the one construct still in PostgreSQL form and the
BigQuery replacement, or states that none exists), and `context_tables`
(every table's backticked BigQuery name). `views` holds the same for
view bodies.

Output: `artifacts/translation-resolutions.json`:

```json
{
  "views": {"public.some_view": {"sql": "SELECT ...", "rationale": "...",
                                 "source_sql": "<copied from the review file>"}},
  "policies": {"public.orders/tenant": {"sql": "(tenant_id = 7)",
                                        "rationale": "single tenant on target",
                                        "source_sql": "<copied from the review file>"}}
}
```

`source_sql` is the review item's `source_sql`, copied unchanged: the
planner compares it with the predicate the source has now, so a
resolution written against an older policy text is rejected instead of
applied. `rationale` is mandatory.

Rules the planner enforces on the next `bq-security plan`:

- A policy resolution is one boolean expression usable inside `FILTER
  USING ( ... )`. It replaces the translated text of that one source
  policy; the planner still combines it with the other policies of the
  table and role. Confidence becomes `resolved`, the rationale is
  appended to the policy's notes, and NOTE `translation_resolved` is
  raised for Gate 1.
- A resolution is applied only to a `review` translation; one recorded
  for a predicate that translated automatically is ignored with WARNING
  `translation_resolution_ignored`. A resolution without a rationale
  (`translation_resolution_unjustified`), with a `source_sql` that no
  longer equals the source predicate (`translation_resolution_stale`),
  or whose `sql` is not one balanced expression or carries a semicolon
  (`translation_resolution_malformed`, because the live backend hands
  the filter to `bq query`, which runs scripts) leaves the policy at
  `review` with that WARNING.
- An empty `sql` does not count: the policy stays `review`, WARNING
  `translation_review` stays, and apply stays blocked. When a construct
  has no BigQuery equivalent, say so in the rationale and leave `sql`
  empty rather than inventing a predicate; the operator then changes
  the source policy or the design.
- The source predicate remains the ground truth for the probe's
  expected row count; the probe note records that the target filter is
  a resolution.
- The agent never edits any other file and never approves its own
  work: Gate 1 shows every resolution with its rationale.
