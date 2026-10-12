"""Security plan for BigQuery: IAM bindings, policy tags, row access policies.

plan_security is a pure function over the security inventory (security.py),
the source inventory (inventory.py), the bigquery block of migration.yaml,
and the principal map. It implements spec section 7 rule by rule and
records every judgment call as a finding with a severity, so Gate 1 can
show the operator exactly what the target will and will not enforce.

The mapping in one paragraph: PostgreSQL role memberships are flattened
(INHERIT closure), PUBLIC is folded into every role, relation privileges
become dataViewer or dataEditor on the table, view, or dataset, column
privileges become policy tags under one enforced taxonomy, and row-level
security becomes one BigQuery row access policy per (table, role) whose
predicate combines the source policies applicable to that role. Nothing
in the plan widens access: every binding traces back to a source
privilege, and a predicate the translator could not finish blocks apply
until the sql-translator agent resolves it.

apply_plan drives a bq_backend.Backend in a fixed order (taxonomy, tags,
tag readers, project, dataset, table bindings, column tags, row
policies). verify_plan reads everything back through the backend, never
trusts the apply log, and also reports pipeline-owned controls the plan
does not name. probe_set and run_probes exercise the controls as each
mapped principal: the expected status comes from the plan (what the
target was told to enforce) and the expected row count from the source
(the ground truth). The CLI verbs (plan, apply, verify, probes) write
their artifacts under <workspace>/artifacts/ with LF newlines.
"""
import argparse
import copy
import json
import re
import sys
from pathlib import Path

from db_carry import bq_backend, bq_predicate, bq_types, config, pg

ROLE_VIEWER = "roles/bigquery.dataViewer"
ROLE_EDITOR = "roles/bigquery.dataEditor"
ROLE_META = "roles/bigquery.metadataViewer"
ROLE_JOBUSER = "roles/bigquery.jobUser"
ROLE_OWNER = "roles/bigquery.dataOwner"
ROLE_FGR = "roles/datacatalog.categoryFineGrainedReader"
ROLE_MASKED_READER = "roles/bigquerydatapolicy.maskedReader"

WRITE_PRIVS = {"INSERT", "UPDATE", "DELETE", "TRUNCATE"}
# The privileges dataEditor stands in for; anything the source did not
# grant from this set is a widening the plan reports.
DML_PRIVS = {"SELECT", "INSERT", "UPDATE", "DELETE"}
RELATION_KINDS = ("table", "view", "matview")
READ_COMMANDS = ("SELECT", "ALL")
FGAC = "FINE_GRAINED_ACCESS_CONTROL"
SEVERITY_RANK = {"WARNING": 0, "INFO": 1, "NOTE": 2}
CONFIDENCE_RANK = {"review": 0, "resolved": 1, "auto": 2}
MASKING_MODE = "policy_tags_with_masking"

PLAN_FILE = "security-plan.json"
PLAN_MD = "security-plan.md"
APPLIED_FILE = "security-applied.json"
VERIFY_FILE = "security-verify.json"
PROBES_FILE = "security-probes.json"
REVIEW_FILE = "translation-review.json"
RESOLUTIONS_FILE = "translation-resolutions.json"
APPLY_DIR = "bq-apply"

ERROR_PREFIX = "BQ-SECURITY ERROR"

_YAML_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")
_TAG_NAME_RE = re.compile(
    r"^projects/[^/]+/locations/([^/]+)/taxonomies/([^/]+)/policyTags/([^/]+)$")
# Data roles by strength. A member holding a stronger role on a resource
# never also gets a weaker one there, and a dataset-level role covers the
# member's table bindings inside that dataset.
_ROLE_RANK = {ROLE_OWNER: 3, ROLE_EDITOR: 2, ROLE_VIEWER: 1, ROLE_META: 0}
# Findings that record the plan granting read access a role lacks on the
# source. probe_set names them in a note instead of expecting a denial.
WIDENING_CODES = ("editor_widens", "widened_by_granularity",
                  "schema_create_widens", "superuser_mapped",
                  "principal_shared")
# The first PostgreSQL major version with per-membership INHERIT options.
MEMBERSHIP_OPTIONS_MAJOR = 16


class SecurityPlanError(Exception):
    pass


# ------------------------------------------------------------ small helpers

def _key(schema, name):
    return f"{schema}.{name}"


def _quote_pg(schema, name):
    return bq_types.quote_pg(schema) + "." + bq_types.quote_pg(name)


def _normalize_ws(text):
    return " ".join(str(text or "").split())


def _is_wrapped(sql):
    """True when sql is one parenthesized group, quotes respected."""
    s = sql.strip()
    if not s.startswith("(") or not s.endswith(")"):
        return False
    depth = 0
    quote = None
    for idx, ch in enumerate(s):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and idx != len(s) - 1:
                return False
    return depth == 0


def _paren(sql):
    s = sql.strip()
    return s if _is_wrapped(s) else f"({s})"


def filter_sql_problem(sql):
    """None when sql is one balanced expression, else a short reason.

    Quote-aware (single, double, and backtick quoted runs are skipped,
    doubled quotes inside them included) and comment-aware (-- to end of
    line, /* */). A semicolon outside quotes, a parenthesis that closes
    more than were opened, or an unclosed parenthesis or quote is a
    problem. The backend's own check runs as well when it exists.
    """
    text = str(sql or "")
    if not text.strip():
        return "empty"
    depth = 0
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in ("'", '"', "`"):
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == ch:
                    if j + 1 < n and text[j + 1] == ch:
                        j += 2
                        continue
                    break
                j += 1
            if j >= n:
                return "unclosed quote"
            i = j + 1
            continue
        if text.startswith("--", i):
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                return "unclosed comment"
            i = j + 2
            continue
        if ch == ";":
            return "semicolon outside a string"
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return "a parenthesis closes more than were opened"
        i += 1
    if depth != 0:
        return "unbalanced parentheses"
    check = getattr(bq_backend, "check_filter_sql", None)
    if check is not None:
        try:
            check(text)
        except Exception as exc:   # BackendError or SqlSyntaxError
            return str(exc)
    return None


def combine_predicates(permissive, restrictive):
    """PostgreSQL policy combination: (p1 OR p2 ...) AND r1 AND r2 ...

    A single permissive predicate with no restrictive one is returned as
    written. Used for the BigQuery filter and for the PostgreSQL count
    query of the probes, so both sides combine the same way.
    """
    perm = [p.strip() for p in permissive if p and p.strip()]
    restr = [r.strip() for r in restrictive if r and r.strip()]
    if not perm:
        return ""
    if len(perm) == 1 and not restr:
        return perm[0]
    head = " OR ".join(_paren(p) for p in perm)
    if not restr:
        return head
    if len(perm) > 1:
        head = f"({head})"
    else:
        head = _paren(perm[0])
    return head + "".join(f" AND {_paren(r)}" for r in restr)


_PRINCIPAL_VALUE_RE = re.compile(r"^[A-Za-z0-9._%+@:?=/-]+$")
_EMAIL_KINDS = ("user", "group", "serviceAccount", "domain")


def _check_principal(label, member):
    try:
        bq_backend._check_member(member)
    except bq_backend.BackendError as exc:
        raise SecurityPlanError(f"{label}: {exc}")
    value = str(member).partition(":")[2]
    if not _PRINCIPAL_VALUE_RE.match(value):
        raise SecurityPlanError(
            f"{label}: principal {member!r} contains a character outside "
            "letters, digits, and . _ % + @ : ? = / -")


def canonical_principal(member):
    """One spelling per principal: IAM compares the address of a user,
    group, service account, or domain without case, so two case variants
    of one address are one principal here too and share one set of
    bindings (and one principal_shared note)."""
    kind, sep, value = str(member or "").partition(":")
    if sep and kind in _EMAIL_KINDS:
        return f"{kind}:{value.lower()}"
    return str(member or "")


def _memberships(security_inv):
    """Membership rows; synthesized from roles[].member_of when the
    inventory predates the memberships section. Synthesized rows carry
    no inherit_option, so the member's INHERIT attribute decides."""
    rows = security_inv.get("memberships")
    if rows is None:
        rows = [{"member": r["name"], "group": g, "admin_option": False,
                 "set_option": True}
                for r in security_inv.get("roles", [])
                for g in r.get("member_of", [])]
    return rows


def parse_server_major(version):
    """Major version from "17.5", "15", or a server_version_num such as
    170005; None when unknown."""
    if version is None:
        return None
    m = re.match(r"\s*(\d+)", str(version))
    if not m:
        return None
    n = int(m.group(1))
    return n // 10000 if n >= 10000 else n


def _inventory_version(inventory):
    return ((inventory or {}).get("server") or {}).get("version")


def membership_inherits(row, member_role, server_major):
    """Whether one membership row carries the group's privileges.

    PostgreSQL 16 and later decide per membership (GRANT ... WITH
    INHERIT), so on such a server the row's inherit_option alone counts,
    whatever the member's INHERIT attribute says. Before 16 the member's
    attribute decides (the inventory records inherit_option true for
    those rows). A row without inherit_option, such as one synthesized
    from member_of, follows the attribute too. With an unknown server
    version both must allow, which can only narrow access.
    """
    attr = bool((member_role or {}).get("inherit", True))
    if "inherit_option" not in row:
        return attr
    option = bool(row.get("inherit_option"))
    if server_major is not None and server_major >= MEMBERSHIP_OPTIONS_MAJOR:
        return option
    return attr and option


def _require_columns(inventory):
    """The plan needs the v0.2.0 inventory: without column rows every
    table would look unreadable, which must never pass silently."""
    if "columns" not in (inventory or {}):
        raise SecurityPlanError(
            "inventory.json has no columns section, so column privileges "
            "cannot be mapped; re-run the assess phase with dbcarry v0.2.0 "
            "(inventory --out artifacts/inventory.json) and plan again")


def _is_system_schema(schema):
    return str(schema).startswith("pg_")


def relation_index(inventory, bq_cfg):
    """{"schema.name": {schema, name, kind, dataset, bq_name}} for every
    table, view, and materialized view of the inventory."""
    dataset_map = bq_cfg.get("dataset_map") or {}
    dbname = bq_cfg.get("dbname") or ""
    out = {}

    def add(schema, name, kind):
        out[_key(schema, name)] = {
            "schema": schema, "name": name, "kind": kind,
            "dataset": bq_types.dataset_for(schema, dataset_map, dbname),
            "bq_name": bq_types.sanitize_identifier(name)[0]}

    for t in inventory.get("tables", []):
        add(t["schema"], t["name"], "table")
    for v in inventory.get("views", []):
        schema, _, name = str(v).partition(".")
        add(schema, name, "view")
    for v in inventory.get("matviews", []):
        schema, _, name = str(v).partition(".")
        add(schema, name, "matview")
    return out


def columns_index(inventory):
    """{"schema.table": [column dicts in ordinal order]}."""
    out = {}
    for c in inventory.get("columns", []):
        out.setdefault(_key(c["schema"], c["table"]), []).append(c)
    for cols in out.values():
        cols.sort(key=lambda c: (c.get("ordinal") or 0, c["name"]))
    return out


def translate_context(relations, project, columns=None):
    """context for bq_predicate.translate: every relation by bare and
    qualified name, plus the columns of the table at hand."""
    tables = {}
    for key, rel in relations.items():
        target = bq_types.qualified(project, rel["dataset"], rel["bq_name"])
        tables[rel["name"]] = target
        tables[key] = target
    return {"tables": tables, "columns": list(columns or [])}


# ------------------------------------------------------- effective privileges

def effective_privileges(security_inv, server_version=None):
    """Flatten grants per role (spec 7.1).

    Returns {role: {"relations": {"schema.name": set(privs)},
                    "columns": {"schema.name": {col: set(privs)}},
                    "schemas": {schema: set(privs)},
                    "inherits_from": [group, ...],
                    "superuser": bool, "bypass_rls": bool, "inherit": bool}}

    PUBLIC's grants are folded into every role. Memberships are followed
    transitively, one edge at a time, and each edge is taken or not by
    membership_inherits: on PostgreSQL 16 and later the membership's own
    inherit option decides, before 16 the member's INHERIT attribute
    does, and with server_version unknown both must allow (the
    conservative rule). server_version is the source server's version
    ("17.5", or a server_version_num such as 170005); plan_security and
    probe_set pass the one recorded in inventory.json. Grantees that are
    not roles of the inventory (pg_database_owner and other pseudo roles)
    are ignored. Temporary schemas (pg_temp_N) are skipped.
    """
    major = parse_server_major(server_version)
    roles = {r["name"]: r for r in security_inv.get("roles", [])}
    direct = {}
    for m in _memberships(security_inv):
        direct.setdefault(m["member"], {})[m["group"]] = m

    def closure(name):
        seen, stack, visited = [], [name], {name}
        while stack:
            cur = stack.pop()
            edges = sorted(direct.get(cur, {}).items(), key=lambda kv: kv[0])
            for group, row in edges:
                if group in visited or group not in roles:
                    continue
                if not membership_inherits(row, roles.get(cur), major):
                    continue
                visited.add(group)
                seen.append(group)
                stack.append(group)
        return sorted(seen)

    grants = {}   # grantee -> ("rel"|"col"|"schema", key, col, priv)

    def grant(grantee, kind, key, col, priv):
        grants.setdefault(grantee, []).append((kind, key, col, priv))

    for row in security_inv.get("schema_privileges", []):
        if _is_system_schema(row["schema"]):
            continue
        grant(row["grantee"], "schema", row["schema"], None, row["privilege"])
    for row in security_inv.get("relation_privileges", []):
        grant(row["grantee"], "rel", _key(row["schema"], row["relation"]),
              None, row["privilege"])
    for row in security_inv.get("column_privileges", []):
        grant(row["grantee"], "col", _key(row["schema"], row["relation"]),
              row["column"], row["privilege"])

    out = {}
    for name, r in roles.items():
        entry = {"relations": {}, "columns": {}, "schemas": {},
                 "inherits_from": closure(name),
                 "superuser": bool(r.get("superuser")),
                 "bypass_rls": bool(r.get("bypass_rls")),
                 "inherit": bool(r.get("inherit", True))}
        sources = [name, "PUBLIC"] + entry["inherits_from"]
        for src in sources:
            for kind, key, col, priv in grants.get(src, []):
                if kind == "schema":
                    entry["schemas"].setdefault(key, set()).add(priv)
                elif kind == "rel":
                    entry["relations"].setdefault(key, set()).add(priv)
                else:
                    entry["columns"].setdefault(key, {}).setdefault(
                        col, set()).add(priv)
        out[name] = entry
    return out


def public_privileges(security_inv):
    """PUBLIC's own grants in the same shape as one effective entry."""
    entry = {"relations": {}, "columns": {}, "schemas": {},
             "inherits_from": [], "superuser": False, "bypass_rls": False,
             "inherit": True}
    for row in security_inv.get("schema_privileges", []):
        if row["grantee"] == "PUBLIC" and not _is_system_schema(row["schema"]):
            entry["schemas"].setdefault(row["schema"], set()).add(
                row["privilege"])
    for row in security_inv.get("relation_privileges", []):
        if row["grantee"] == "PUBLIC":
            entry["relations"].setdefault(
                _key(row["schema"], row["relation"]), set()).add(
                row["privilege"])
    for row in security_inv.get("column_privileges", []):
        if row["grantee"] == "PUBLIC":
            entry["columns"].setdefault(
                _key(row["schema"], row["relation"]), {}).setdefault(
                row["column"], set()).add(row["privilege"])
    return entry


def readable_columns(eff, inventory, public=None):
    """{"schema.table": {role: set(columns)}} (spec 7.3).

    Every column when the role has table SELECT, otherwise the columns
    with column-level SELECT. Roles that read nothing are absent. A table
    with SELECT but no column rows in the inventory maps to an empty
    set: the role does read the table (test membership, not truthiness),
    and the plan flags the missing rows as inventory_without_columns.
    Superusers are left out: they bypass column privileges, so they do
    not define what is restricted (a mapped superuser gets every tag).
    """
    cols_by_table = columns_index(inventory)
    keys = [_key(t["schema"], t["name"]) for t in inventory.get("tables", [])]
    keys += [k for k in cols_by_table if k not in keys]
    readers = dict(eff)
    if public is not None:
        # a public principal reads exactly what PUBLIC was granted, so
        # PUBLIC takes part in the restricted-column computation as a
        # reader of its own (spec 7.3): a column-level PUBLIC grant must
        # never become a full table read for that principal
        readers["PUBLIC"] = {"relations": public.get("relations", {}),
                             "columns": public.get("columns", {}),
                             "superuser": False}
    out = {}
    for key in keys:
        names = [c["name"] for c in cols_by_table.get(key, [])]
        per_role = {}
        for role, e in readers.items():
            if e.get("superuser"):
                continue
            if "SELECT" in e["relations"].get(key, set()):
                per_role[role] = set(names)
                continue
            granted = {c for c, privs in e["columns"].get(key, {}).items()
                       if "SELECT" in privs and c in names}
            if granted:
                per_role[role] = granted
        out[key] = per_role
    return out


def restricted_columns(readable, inventory):
    """{"schema.table": {column: frozenset(roles allowed)}} (spec 7.3).

    A column is restricted when some role that reads at least one column
    of the table cannot read it. Columns keep inventory order.
    """
    cols_by_table = columns_index(inventory)
    out = {}
    for key, per_role in readable.items():
        readers = set(per_role)
        if not readers:
            continue
        restricted = {}
        for c in cols_by_table.get(key, []):
            allowed = frozenset(r for r in readers if c["name"] in per_role[r])
            if allowed != readers:
                restricted[c["name"]] = allowed
        if restricted:
            out[key] = restricted
    return out


# --------------------------------------------------------------- the planner

class _Planner:
    def __init__(self, security_inv, inventory, bq_cfg, principal_map,
                 resolutions):
        self.sec = security_inv
        self.inv = inventory
        self.cfg = bq_cfg
        self.project = bq_cfg.get("project") or config.BQ_DEFAULTS["project"]
        self.location = bq_cfg.get("location") or config.BQ_DEFAULTS["location"]
        self.mode = bq_cfg.get("mode") or "emulated"
        self.migration = bq_cfg.get("migration") or "migration"
        self.granularity = bq_cfg.get("binding_granularity") or "auto"
        if self.granularity not in ("auto", "dataset", "table"):
            raise SecurityPlanError(
                f"binding_granularity must be auto, dataset, or table, got "
                f"{self.granularity!r}")
        self.admin = str(bq_cfg.get("admin_principal") or "")
        self.public_principal = str(bq_cfg.get("public_principal") or "")
        self.masking = (bq_cfg.get("column_security") or "") == MASKING_MODE
        if self.admin:
            _check_principal("admin_principal", self.admin)
            self.admin = canonical_principal(self.admin)
        if self.public_principal:
            _check_principal("public_principal", self.public_principal)
            self.public_principal = canonical_principal(self.public_principal)
        self.resolutions = (resolutions or {}).get("policies") or {}
        _require_columns(inventory)
        self.server_version = _inventory_version(inventory)
        self.server_major = parse_server_major(self.server_version)

        self.roles = {r["name"]: r for r in security_inv.get("roles", [])}
        self.eff = effective_privileges(security_inv,
                                        server_version=self.server_version)
        self.public = public_privileges(security_inv)
        self.relations = relation_index(inventory, bq_cfg)
        self.columns = columns_index(inventory)
        self.datasets = {}
        for key in sorted(self.relations):
            rel = self.relations[key]
            self.datasets.setdefault(rel["dataset"],
                                     {"source_schema": rel["schema"]})
        self.relations_by_dataset = {}
        for key, rel in self.relations.items():
            self.relations_by_dataset.setdefault(rel["dataset"], set()).add(key)
        self.owners = {}
        for row in security_inv.get("relation_privileges", []):
            self.owners[_key(row["schema"], row["relation"])] = row.get("owner")
        self.kinds = {}
        for row in security_inv.get("relation_privileges", []):
            self.kinds[_key(row["schema"], row["relation"])] = row.get("kind")

        self.principals = {}
        self.probe_sa = {}
        self.findings = []
        for name, entry in sorted((principal_map or {}).get("roles", {}).items()):
            principal = str((entry or {}).get("principal") or "")
            if name not in self.roles:
                self.finding("INFO", "principal_without_role", name,
                             f"the principal map names {name}, which is not "
                             "a role on the source",
                             "remove the entry or check the role name")
                continue
            if not principal:
                continue
            _check_principal(f"principal map: role {name}", principal)
            self.principals[name] = canonical_principal(principal)
            self.probe_sa[name] = str(
                (entry or {}).get("probe_service_account") or "")

        self.readable = readable_columns(
            self.eff, inventory, self.public if self.public_principal else None)
        self.restricted = restricted_columns(self.readable, inventory)
        self.rls_tables = {
            _key(r["schema"], r["relation"]): r
            for r in security_inv.get("rls", []) if r.get("enabled")}
        self.policies_by_table = {}
        for p in security_inv.get("policies", []):
            self.policies_by_table.setdefault(
                _key(p["schema"], p["relation"]), []).append(p)
        self.context_tables = translate_context(self.relations,
                                                self.project)["tables"]
        self._translated = {}
        self.identity_notes = []
        self.would_receive = {}   # unmapped role -> [what it would get]
        # review-flagged source policies: ref -> {key, name, notes, roles,
        # emitted}; the finding is decided once the row policies exist
        self.review_refs = {}

    # ---- findings

    def finding(self, severity, code, subject, message, action):
        self.findings.append({"severity": severity, "code": code,
                              "subject": subject, "message": message,
                              "action": action})

    def note_unmapped(self, role, what):
        self.would_receive.setdefault(role, []).append(what)

    def is_superuser(self, role):
        return bool(self.eff.get(role, {}).get("superuser"))

    def mapped(self, role):
        return role in self.principals

    def resource(self, key):
        rel = self.relations[key]
        return f"{rel['dataset']}.{rel['bq_name']}"

    # ---- per-role controls

    def role_controls(self, role, eff_entry, member=None):
        """Bindings one non-superuser role earns from its effective grants.

        member is the principal the bindings will name (it appears in
        finding subjects); it defaults to the role's principal, or the
        role name when unmapped.
        Returns {"relation_roles": {"schema.name": iam role},
                 "dataset_roles": {dataset: {iam role: reason}},
                 "reasons": {"schema.name": reason}}.
        """
        member = member or self.principals.get(role, role)
        relation_roles, reasons = {}, {}
        view_writes = []
        self.flag_unmappable(role, eff_entry)
        for key in sorted(eff_entry["relations"]):
            privs = eff_entry["relations"][key]
            rel = self.relations.get(key)
            if rel is None:
                continue
            reads = "SELECT" in privs
            writes = privs & WRITE_PRIVS
            if rel["kind"] == "table":
                if writes:
                    relation_roles[key] = ROLE_EDITOR
                    reasons[key] = f"{', '.join(sorted(privs & DML_PRIVS | writes))} on {key}"
                    added = sorted(DML_PRIVS - privs)
                    if added:
                        self.finding(
                            "WARNING", "editor_widens", f"{key}/{role}",
                            f"{role} holds {', '.join(sorted(privs & (DML_PRIVS | WRITE_PRIVS)))} "
                            f"on {key}; BigQuery has no write-only role, so "
                            f"dataEditor also grants {', '.join(added)}",
                            "accept the widening or move the write path to a "
                            "service account of its own")
                elif reads:
                    relation_roles[key] = ROLE_VIEWER
                    reasons[key] = f"SELECT on {key}"
            elif reads:
                relation_roles[key] = ROLE_VIEWER
                reasons[key] = f"SELECT on {rel['kind']} {key}"
                if writes:
                    view_writes.append(key)
            elif writes:
                # a write-only grant on a view: the only binding BigQuery
                # offers is a read one, which the source did not give
                relation_roles[key] = ROLE_VIEWER
                reasons[key] = (f"{', '.join(sorted(writes))} on {rel['kind']} "
                                f"{key} without SELECT")
                self.finding(
                    "WARNING", "view_write_widens", f"{key}/{role}",
                    f"{role} holds {', '.join(sorted(writes))} but not SELECT "
                    f"on {rel['kind']} {key}; BigQuery views are read only "
                    "and have no write role, so the closest binding is "
                    "dataViewer, which lets the role read a view it could "
                    "only write to on the source",
                    "accept the widening, or revoke the write privilege on "
                    "the source so no binding is needed")
        for key in sorted(eff_entry["columns"]):
            rel = self.relations.get(key)
            if rel is None:
                continue
            cols = eff_entry["columns"][key]
            selectable = sorted(c for c, p in cols.items() if "SELECT" in p)
            known = [c["name"] for c in self.columns.get(key, [])]
            if rel["kind"] == "table" and known:
                unknown = [c for c in selectable if c not in known]
                if unknown:
                    self.finding(
                        "WARNING", "column_grant_unknown_column",
                        f"{key}/{role}",
                        f"{role} holds column-level SELECT on "
                        f"{', '.join(unknown)} of {key}, which the "
                        "inventory does not list; no binding is derived "
                        "from a column the plan cannot protect with a tag",
                        "take inventory.json and security.json at the same "
                        "time, or check the column names")
                    selectable = [c for c in selectable if c in known]
            for col in sorted(cols):
                writes = cols[col] & WRITE_PRIVS
                if writes:
                    self.finding(
                        "WARNING", "column_write_unmapped",
                        f"{key}.{col}/{role}",
                        f"{role} holds column-level {', '.join(sorted(writes))} "
                        f"on {key}.{col}; BigQuery has no column-level write "
                        "control",
                        "grant table-level write through a service account "
                        "or keep the column read-only on the target")
            if selectable and key not in relation_roles:
                relation_roles[key] = ROLE_VIEWER
                listed = ", ".join(selectable)
                if rel["kind"] != "table":
                    # the inventory lists columns for tables only, so no
                    # tag can protect the view's other columns
                    reasons[key] = (f"column SELECT on {rel['kind']} {key} "
                                    f"({listed}); every column of the "
                                    f"{rel['kind']} becomes readable")
                    self.finding(
                        "WARNING", "view_column_grant_widens", f"{key}/{role}",
                        f"{role} holds column-level SELECT on {listed} of "
                        f"{rel['kind']} {key}; the inventory lists no columns "
                        "for views, so no policy tag protects the other "
                        "columns and dataViewer on the view exposes all of "
                        "them",
                        "define a view that exposes only those columns and "
                        "grant SELECT on it, or accept the widening")
                elif key in self.restricted:
                    reasons[key] = (f"column SELECT on {key} ({listed}); the "
                                    "restricted columns of the table carry a "
                                    "policy tag")
                elif known and set(selectable) == set(known):
                    reasons[key] = (f"column SELECT on {key} ({listed}), "
                                    "which covers every column")
                else:
                    reasons[key] = f"column SELECT on {key} ({listed})"
        if view_writes:
            self.finding("INFO", "view_write_unmapped", role,
                         f"{role} holds write privileges on "
                         f"{', '.join(view_writes)}; BigQuery views are read "
                         "only, so dataViewer is granted",
                         "nothing to do unless the view was updatable by design")

        dataset_roles = {}
        for schema in sorted(eff_entry["schemas"]):
            privs = eff_entry["schemas"][schema]
            dataset = bq_types.dataset_for(
                schema, self.cfg.get("dataset_map") or {},
                self.cfg.get("dbname") or "")
            if dataset not in self.datasets:
                continue
            in_schema = [k for k in relation_roles
                         if self.relations[k]["schema"] == schema]
            if "CREATE" in privs:
                dataset_roles.setdefault(dataset, {})[ROLE_EDITOR] = \
                    f"CREATE on schema {schema}"
                self.finding(
                    "WARNING", "schema_create_widens", f"{schema}/{role}",
                    f"{role} holds CREATE on schema {schema}; the closest "
                    f"BigQuery role is dataEditor on dataset {dataset}, which "
                    "also reads and writes every table",
                    "accept the widening or drop CREATE for this role")
            elif "USAGE" in privs and not in_schema:
                dataset_roles.setdefault(dataset, {})[ROLE_META] = \
                    f"USAGE on schema {schema} without relation grants"
        self.promote(role, member, relation_roles, dataset_roles, reasons)
        for dataset, per_role in dataset_roles.items():
            if ROLE_EDITOR in per_role:
                # dataEditor includes dataViewer and metadataViewer
                per_role.pop(ROLE_VIEWER, None)
                per_role.pop(ROLE_META, None)
                for key in [k for k, r in relation_roles.items()
                            if self.relations[k]["dataset"] == dataset]:
                    del relation_roles[key]
            elif ROLE_VIEWER in per_role:
                per_role.pop(ROLE_META, None)
        return {"relation_roles": relation_roles,
                "dataset_roles": dataset_roles, "reasons": reasons}

    def flag_unmappable(self, role, eff_entry):
        """INFO findings for grants with no BigQuery counterpart:
        sequences, and REFERENCES, TRIGGER, MAINTAIN on relations."""
        sequences, unmappable = [], set()
        for key in sorted(eff_entry["relations"]):
            privs = eff_entry["relations"][key]
            if key in self.relations:
                unmappable |= privs - DML_PRIVS - {"TRUNCATE"}
            elif self.kinds.get(key) == "sequence":
                sequences.append(key)
        if sequences:
            self.finding("INFO", "sequence_unmapped", role,
                         f"{role} holds sequence privileges on "
                         f"{', '.join(sequences)}; BigQuery has no sequences",
                         "nothing to do; identity columns are not migrated")
        if unmappable:
            self.finding("INFO", "privilege_unmapped", role,
                         f"{role} holds {', '.join(sorted(unmappable))}, which "
                         "have no BigQuery equivalent",
                         "nothing to do")

    def promote(self, role, member, relation_roles, dataset_roles, reasons):
        """Granularity rule: move per-relation roles to dataset scope.

        auto promotes an IAM role only when the role holds it on every
        relation of the dataset. dataset promotes the strongest IAM role
        the role holds anywhere in the dataset and reports, once per
        (dataset, member), the relations where the source grants less
        (read only) and those where it grants nothing. table never
        promotes.
        """
        if self.granularity == "table":
            return
        for dataset in sorted(self.relations_by_dataset):
            everything = self.relations_by_dataset[dataset]
            holders = {k: r for k, r in relation_roles.items()
                       if self.relations[k]["dataset"] == dataset}
            if not holders:
                continue
            if self.granularity == "auto":
                for iam_role in (ROLE_EDITOR, ROLE_VIEWER):
                    mine = {k for k, r in holders.items() if r == iam_role}
                    if not mine or mine != everything:
                        continue
                    for key in mine:
                        del relation_roles[key]
                        reasons.pop(key, None)
                    dataset_roles.setdefault(dataset, {})[iam_role] = (
                        f"same role on every relation of dataset {dataset}")
                continue
            top = (ROLE_EDITOR if ROLE_EDITOR in holders.values()
                   else ROLE_VIEWER)
            same = sorted(k for k, r in holders.items() if r == top)
            lesser = sorted(k for k in holders if k not in same)
            missing = sorted(everything - set(holders))
            if not lesser and not missing:
                reason = f"same role on every relation of dataset {dataset}"
            else:
                reason = (f"binding_granularity dataset: {len(same)} of "
                          f"{len(everything)} relations")
                detail = []
                if lesser:
                    detail.append("read only on the source: "
                                  + ", ".join(lesser))
                if missing:
                    detail.append("no grant on the source: "
                                  + ", ".join(missing))
                self.finding(
                    "WARNING", "widened_by_granularity",
                    f"{dataset}/{member}",
                    f"{member} ({role}) gets {top.split('.')[-1]} on dataset "
                    f"{dataset} although the source grants that level on "
                    f"only {len(same)} of {len(everything)} relations; "
                    + "; ".join(detail),
                    "set binding_granularity to auto or table to keep "
                    "per-table bindings")
            for key in holders:
                del relation_roles[key]
                reasons.pop(key, None)
            dataset_roles.setdefault(dataset, {})[top] = reason

    # ---- bindings

    def bindings_from_controls(self, controls, member, source_role, out):
        for key in sorted(controls["relation_roles"]):
            out.append({"scope": "table", "resource": self.resource(key),
                        "role": controls["relation_roles"][key],
                        "member": member, "source_role": source_role,
                        "reason": controls["reasons"].get(key, "")})
        for dataset in sorted(controls["dataset_roles"]):
            for iam_role, reason in sorted(
                    controls["dataset_roles"][dataset].items()):
                out.append({"scope": "dataset", "resource": dataset,
                            "role": iam_role, "member": member,
                            "source_role": source_role, "reason": reason})

    def describe_controls(self, controls):
        items = []
        for key, iam_role in sorted(controls["relation_roles"].items()):
            items.append(f"{iam_role.split('.')[-1]} on {self.resource(key)}")
        for dataset, per_role in sorted(controls["dataset_roles"].items()):
            for iam_role in sorted(per_role):
                items.append(f"{iam_role.split('.')[-1]} on dataset {dataset}")
        return items

    def build_bindings(self):
        bindings = []
        controls_by_role = {}
        for role in sorted(self.roles):
            entry = self.eff[role]
            if entry["superuser"]:
                continue
            controls = self.role_controls(role, entry)
            controls_by_role[role] = controls
            if self.mapped(role):
                self.bindings_from_controls(controls, self.principals[role],
                                            role, bindings)
            else:
                for item in self.describe_controls(controls):
                    self.note_unmapped(role, item)
        # superusers
        for role in sorted(self.roles):
            if not self.is_superuser(role):
                continue
            self.flag_unmappable(role, self.eff[role])
            if self.mapped(role):
                for dataset in sorted(self.datasets):
                    bindings.append({
                        "scope": "dataset", "resource": dataset,
                        "role": ROLE_OWNER, "member": self.principals[role],
                        "source_role": role,
                        "reason": f"superuser {role} on the source"})
                self.finding(
                    "WARNING", "superuser_mapped", role,
                    f"superuser {role} is mapped to {self.principals[role]}: "
                    "dataOwner on every dataset, reader on every policy tag, "
                    "and a FILTER USING (TRUE) row policy on every RLS table",
                    "map a superuser only when a bypass principal is wanted")
            else:
                self.finding(
                    "INFO", "superuser_unmapped", role,
                    f"superuser {role} has no principal; the migration "
                    "identity owns the datasets instead",
                    "nothing to do unless a bypass principal is wanted")
        # PUBLIC
        has_rel = bool(self.public["relations"] or self.public["columns"])
        if has_rel or self.public["schemas"]:
            if self.public_principal:
                controls = self.role_controls("PUBLIC", self.public,
                                              member=self.public_principal)
                self.bindings_from_controls(controls, self.public_principal,
                                            "PUBLIC", bindings)
                self.finding(
                    "NOTE", "public_mapped", "PUBLIC",
                    f"PUBLIC grants are bound to {self.public_principal} "
                    "(besides being folded into every role); this principal "
                    "should be a group that holds every user of the source",
                    "check the group membership")
            elif has_rel:
                rels = sorted(set(self.public["relations"])
                              | set(self.public["columns"]))
                self.finding(
                    "WARNING", "public_unmapped", "PUBLIC",
                    f"PUBLIC holds grants on {', '.join(rels)}; every source "
                    "role received them through folding, but no BigQuery "
                    "principal stands for PUBLIC itself (dbcarry never maps "
                    "it to allUsers or allAuthenticatedUsers)",
                    "set bigquery.public_principal to a group holding every "
                    "user, or accept that only inventoried roles keep access")
            else:
                self.finding(
                    "NOTE", "public_schema_usage", "PUBLIC",
                    "PUBLIC holds USAGE on schema "
                    f"{', '.join(sorted(self.public['schemas']))} and nothing "
                    "else; it is folded into every role and no separate "
                    "principal is bound",
                    "nothing to do")
        # jobUser once per member
        members = {}
        for b in bindings:
            members.setdefault(b["member"], b["source_role"])
        for member, source_role in members.items():
            bindings.append({"scope": "project", "resource": self.project,
                             "role": ROLE_JOBUSER, "member": member,
                             "source_role": source_role,
                             "reason": "needed to run queries"})
        # dedupe and sort
        seen, unique = set(), []
        for b in sorted(bindings, key=lambda b: (
                b["scope"], b["resource"], b["role"], b["member"],
                b["source_role"])):
            sig = (b["scope"], b["resource"], b["role"], b["member"])
            if sig in seen:
                continue
            seen.add(sig)
            unique.append(b)
        return self.absorb_bindings(unique), controls_by_role

    def absorb_bindings(self, bindings):
        """One data role per (scope, resource, member): the strongest
        wins, and a dataset-level role also covers the member's table
        bindings inside that dataset. Only a principal shared by several
        source roles produces such overlaps, so every shared principal
        gets a NOTE principal_shared listing the roles and whatever was
        absorbed. jobUser bindings are left alone."""
        best = {}
        for b in bindings:
            if b["role"] not in _ROLE_RANK:
                continue
            sig = (b["scope"], b["resource"], b["member"])
            cur = best.get(sig)
            if cur is None or _ROLE_RANK[b["role"]] > _ROLE_RANK[cur["role"]]:
                best[sig] = b
        kept, absorbed = [], {}
        for b in bindings:
            if b["role"] not in _ROLE_RANK:
                kept.append(b)
                continue
            winner = best[(b["scope"], b["resource"], b["member"])]
            if winner is b and b["scope"] == "table":
                dataset = b["resource"].partition(".")[0]
                above = best.get(("dataset", dataset, b["member"]))
                if above is not None and \
                        _ROLE_RANK[above["role"]] >= _ROLE_RANK[b["role"]]:
                    winner = above
            if winner is b:
                kept.append(b)
                continue
            absorbed.setdefault(b["member"], []).append(
                f"{b['role'].split('.')[-1]} on {b['resource']} "
                f"({b['source_role']}) is covered by "
                f"{winner['role'].split('.')[-1]} on {winner['resource']} "
                f"({winner['source_role']})")
        roles_by_member = {}
        for role, member in sorted(self.principals.items()):
            roles_by_member.setdefault(member, []).append(role)
        if self.public_principal:
            roles_by_member.setdefault(self.public_principal, []).append(
                "PUBLIC")
        for member, roles in sorted(roles_by_member.items()):
            if len(roles) < 2:
                continue
            detail = absorbed.get(member)
            self.finding(
                "NOTE", "principal_shared", member,
                f"{', '.join(roles)} all map to {member}, which therefore "
                "holds the union of their access"
                + ("; absorbed bindings: " + "; ".join(detail) if detail
                   else "; their bindings do not overlap"),
                "confirm that one principal for several roles is intended; "
                "probes for these roles expect the union")
        return kept

    # ---- policy tags

    def build_tags(self):
        tags = []
        used = set()
        superusers = [r for r in sorted(self.roles)
                      if self.is_superuser(r) and self.mapped(r)]
        for key in sorted(self.restricted):
            rel = self.relations.get(key)
            if rel is None:
                continue
            groups = []   # [(allowed, [columns])] in first-column order
            for col, allowed in self.restricted[key].items():
                for entry in groups:
                    if entry[0] == allowed:
                        entry[1].append(col)
                        break
                else:
                    groups.append((allowed, [col]))
            for allowed, cols in groups:
                base = f"{rel['bq_name']}__{cols[0]}"
                if len(cols) > 1:
                    base += f"_and_{len(cols) - 1}_more"
                name = bq_types.sanitize_identifier(base)[0]
                if name in used:
                    name = bq_types.sanitize_identifier(
                        f"{rel['dataset']}__{base}")[0]
                used.add(name)
                readers = []
                for role in sorted(allowed):
                    if role == "PUBLIC":
                        readers.append({"member": self.public_principal,
                                        "source_role": "PUBLIC"})
                    elif self.mapped(role):
                        readers.append({"member": self.principals[role],
                                        "source_role": role})
                    elif not self.is_superuser(role):
                        self.note_unmapped(
                            role, f"fine-grained reader on tag {name}")
                for role in superusers:
                    readers.append({"member": self.principals[role],
                                    "source_role": role})
                readers.sort(key=lambda r: (r["member"], r["source_role"]))
                source_columns = [f"{key}.{c}" for c in cols]
                who = ", ".join(sorted(allowed)) or "nobody"
                tags.append({
                    "name": name,
                    "columns": [{"dataset": rel["dataset"],
                                 "table": rel["bq_name"], "column": c}
                                for c in cols],
                    "readers": readers,
                    "source_columns": source_columns,
                    "description": f"dbcarry: {', '.join(source_columns)} "
                                   f"readable by {who}"})
        tags.sort(key=lambda t: t["name"])
        return tags

    def build_masking(self, tags):
        if not self.masking:
            return []
        out = []
        for tag in tags:
            key = tag["source_columns"][0].rsplit(".", 1)[0]
            allowed = {r["source_role"] for r in tag["readers"]}
            masked = sorted({self.principals[r]
                             for r in self.readable.get(key, {})
                             if self.mapped(r) and r not in allowed})
            out.append({"tag": tag["name"],
                        "data_policy_id": f"mask_{tag['name']}",
                        "rule": "ALWAYS_NULL", "masked_readers": masked})
        return out

    # ---- row policies

    def resolution_problem(self, resolution, res_sql, pol):
        """Why a recorded resolution cannot be applied, as (code, message,
        action), or None when it can. A resolution needs a rationale (Gate
        1 shows it), must be written against the predicate the source has
        now (source_sql, when the agent recorded it, must equal the
        current USING clause), and must be one balanced boolean
        expression: the live backend hands the filter to bq query, which
        runs scripts, so a stray parenthesis or semicolon would execute
        whatever follows it."""
        rationale = str(resolution.get("rationale") or "").strip()
        name = pol["name"]
        if not rationale:
            return ("translation_resolution_unjustified",
                    f"the resolution for policy {name} has no rationale; "
                    "it stays at review",
                    "have the sql-translator state why the text keeps the "
                    "source semantics")
        recorded = resolution.get("source_sql")
        if recorded is not None and \
                _normalize_ws(str(recorded)) != _normalize_ws(pol.get("using") or ""):
            return ("translation_resolution_stale",
                    f"the resolution for policy {name} was written against "
                    f"the predicate {str(recorded).strip()}, but the source "
                    f"now has {str(pol.get('using') or '').strip()}; it "
                    "stays at review",
                    "re-run the sql-translator against the current review "
                    "file")
        why = filter_sql_problem(res_sql)
        if why is not None:
            return ("translation_resolution_malformed",
                    f"the resolution for policy {name} is not one balanced "
                    f"boolean expression ({why}); it stays at review",
                    "return a single expression with balanced parentheses "
                    "and no semicolon")
        return None

    def translate_policy(self, key, pol):
        """Translate one source policy's USING clause once per table."""
        cache_key = (key, pol["name"])
        if cache_key in self._translated:
            return self._translated[cache_key]
        rel = self.relations[key]
        context = translate_context(self.relations, self.project,
                                    self.columns.get(key, []))
        result = bq_predicate.translate(pol.get("using") or "", context)
        ref = f"{key}/{pol['name']}"
        entry = {"name": pol["name"], "command": pol.get("command"),
                 "permissive": bool(pol.get("permissive", True)),
                 "roles": sorted(pol.get("roles") or []),
                 "using": pol.get("using"), "sql": result["sql"],
                 "confidence": result["confidence"],
                 "notes": list(result["notes"])}
        resolution = self.resolutions.get(ref) or {}
        if not isinstance(resolution, dict):
            raise SecurityPlanError(
                f"translation-resolutions.json entry for {ref} must be an "
                f"object with sql and rationale, not "
                f"{type(resolution).__name__}")
        res_sql = str(resolution.get("sql") or "").strip()
        if res_sql and entry["confidence"] != "review":
            self.finding(
                "WARNING", "translation_resolution_ignored", ref,
                f"translation-resolutions.json carries a resolution for "
                f"policy {pol['name']} on {key}, but its predicate "
                f"translated automatically ({entry['sql']}); a resolution "
                "replaces only a review-flagged translation, so the "
                "recorded one is ignored",
                "remove the entry, or change the source policy if the "
                "automatic translation is wrong")
        elif res_sql:
            problem = self.resolution_problem(resolution, res_sql, pol)
            if problem is not None:
                code, message, action = problem
                self.finding("WARNING", code, ref, message, action)
            else:
                entry["sql"] = res_sql
                entry["confidence"] = "resolved"
                rationale = str(resolution.get("rationale") or "").strip()
                entry["notes"].append(
                    "resolved by the sql-translator agent: " + rationale)
                self.finding("NOTE", "translation_resolved", ref,
                             f"the predicate of policy {pol['name']} on "
                             f"{key} uses the recorded resolution: "
                             f"{entry['sql']}",
                             "confirm the rationale at Gate 1")
        if entry["confidence"] == "review":
            # the finding waits for build_row_policies: it is a blocking
            # WARNING only when an emitted policy carries the predicate
            self.review_refs.setdefault(ref, {
                "key": key, "name": pol["name"],
                "notes": list(entry["notes"]), "roles": set(),
                "emitted": False})
        if "SESSION_USER()" in entry["sql"]:
            identity = [n for n in entry["notes"] if "SESSION_USER" in n]
            self.finding(
                "INFO", "identity_predicate", ref,
                f"policy {pol['name']} on {key} compares a column with the "
                "caller's identity; PostgreSQL sees a role name and BigQuery "
                "SESSION_USER() sees an email address",
                "make sure the column holds Google identities on the target "
                "or add a mapping table; probe counts for this policy are "
                "reported but not compared")
            note = f"{ref}: " + (identity[0] if identity else
                                 bq_predicate.IDENTITY_NOTE.format(
                                     word="current_user"))
            if note not in self.identity_notes:
                self.identity_notes.append(note)
        self._translated[cache_key] = entry
        return entry

    def applicable_policies(self, key, role):
        """Source policies that filter reads for role on table key, with
        the role through which each applies."""
        groups = {role, "PUBLIC"} | set(self.eff[role]["inherits_from"])
        out = []
        for pol in sorted(self.policies_by_table.get(key, []),
                          key=lambda p: p["name"]):
            if pol.get("command") not in READ_COMMANDS or not pol.get("using"):
                continue
            names = set(pol.get("roles") or [])
            if role in names:
                via = role
            elif "PUBLIC" in names:
                via = "PUBLIC"
            else:
                hit = sorted(names & groups)
                if not hit:
                    continue
                via = hit[0]
            out.append((pol, via))
        return out

    def can_read(self, role, key):
        if self.is_superuser(role):
            return True
        # membership, not truthiness: a table without column rows maps
        # to an empty set for a role that holds table SELECT
        return role in self.readable.get(key, {})

    def build_row_policies(self):
        policies = []
        flagged = set()
        for key in sorted(self.rls_tables):
            rel = self.relations.get(key)
            if rel is None or rel["kind"] != "table":
                continue
            forced = bool(self.rls_tables[key].get("forced"))
            for pol in sorted(self.policies_by_table.get(key, []),
                              key=lambda p: p["name"]):
                ref = f"{key}/{pol['name']}"
                unmapped_cmd = pol.get("command") not in READ_COMMANDS
                if (unmapped_cmd or pol.get("with_check")) and ref not in flagged:
                    flagged.add(ref)
                    what = (f"applies to {pol.get('command')}" if unmapped_cmd
                            else "carries a WITH CHECK clause")
                    self.finding(
                        "WARNING", "policy_command_unmapped", ref,
                        f"policy {pol['name']} on {key} {what}; BigQuery row "
                        "access policies filter reads and DML targets but "
                        "cannot check new or changed rows"
                        + ("" if unmapped_cmd else
                           " (its USING clause is still mapped for reads)"),
                        "enforce the write-side rule in the loading pipeline "
                        "or the application")
            if self.public_principal and "PUBLIC" in self.readable.get(key, {}):
                self.finding(
                    "INFO", "public_rls_denied", key,
                    f"PUBLIC holds SELECT on {key}, which has row-level "
                    f"security; row access policies are written per source "
                    f"role only, so {self.public_principal} receives none "
                    "and sees no rows of this table on the target",
                    "map the users behind PUBLIC to roles, or accept that "
                    "the public principal reads nothing here")
            table_policies = []
            for role in sorted(self.roles):
                if self.is_superuser(role):
                    continue
                if not self.can_read(role, key):
                    continue
                # ownership is inherited through membership (superuser
                # status is not), and an owner bypasses RLS unless forced
                owner = self.owners.get(key)
                inherited = bool(owner) and owner != role and \
                    owner in self.eff[role]["inherits_from"]
                owner_bypass = bool(owner) and not forced and \
                    (owner == role or inherited)
                if self.eff[role]["bypass_rls"] or owner_bypass:
                    if self.eff[role]["bypass_rls"]:
                        why = "BYPASSRLS"
                    elif inherited:
                        why = (f"member of {owner}, which owns the table; "
                               "ownership is inherited and RLS is not forced")
                    else:
                        why = "owner of the table, RLS not forced"
                    table_policies.append(self.policy_entry(
                        rel, f"rls_bypass_{role}", [role], "TRUE", "auto",
                        [f"{role} bypasses RLS on the source ({why})"], []))
                    continue
                applicable = self.applicable_policies(key, role)
                permissive = [(p, via) for p, via in applicable
                              if p.get("permissive", True)]
                restrictive = [(p, via) for p, via in applicable
                               if not p.get("permissive", True)]
                if not permissive:
                    self.finding(
                        "INFO", "rls_denies_role", f"{key}/{role}",
                        f"{role} can read {key} but no permissive policy "
                        "names it, so it sees no rows on PostgreSQL; no "
                        "BigQuery policy is written and the table's other "
                        "policies deny it every row",
                        "nothing to do; matches the source")
                    continue
                parts, notes, sources = [], [], []
                for pol, via in permissive + restrictive:
                    entry = dict(self.translate_policy(key, pol))
                    entry["via"] = via
                    sources.append(entry)
                    for n in entry["notes"]:
                        if n not in notes:
                            notes.append(n)
                filter_sql = combine_predicates(
                    [self.translate_policy(key, p)["sql"] for p, _ in permissive],
                    [self.translate_policy(key, p)["sql"] for p, _ in restrictive])
                confidence = min((s["confidence"] for s in sources),
                                 key=lambda c: CONFIDENCE_RANK.get(c, 0))
                sources.sort(key=lambda s: s["name"])
                table_policies.append(self.policy_entry(
                    rel, f"rls_{role}", [role], filter_sql, confidence,
                    notes, sources))
            for role in sorted(self.roles):
                if self.is_superuser(role) and self.mapped(role):
                    table_policies.append(self.policy_entry(
                        rel, f"rls_bypass_{role}", [role], "TRUE", "auto",
                        [f"superuser {role} bypasses RLS on the source"], []))
            emitted = []
            for pol in table_policies:
                role = pol["source_roles"][0]
                mapped = self.mapped(role)
                for src in pol["source_policies"]:
                    if src.get("confidence") != "review":
                        continue
                    item = self.review_refs.get(f"{key}/{src['name']}")
                    if item is not None:
                        item["roles"].add(role)
                        item["emitted"] = item["emitted"] or mapped
                if mapped:
                    pol["members"] = [self.principals[role]]
                    emitted.append(pol)
                else:
                    self.note_unmapped(
                        role, f"row policy {pol['name']} on {key}")
            if not emitted:
                if self.admin:
                    emitted.append(self.policy_entry(
                        rel, "rls_deny_all", [], "FALSE", "auto",
                        ["no mapped role has a read policy on this table; "
                         "without any policy BigQuery would show every row"],
                        [], members=[self.admin]))
                    self.finding(
                        "WARNING", "rls_deny_all", key,
                        f"{key} has row-level security but no mapped role "
                        "gets a read policy; a FILTER USING (FALSE) policy "
                        f"for {self.admin} keeps the table closed, because a "
                        "table without any policy is open to every reader",
                        "expected when the source policies name only "
                        "unmapped roles; otherwise map the roles")
                else:
                    self.finding(
                        "WARNING", "rls_deny_all_unassigned", key,
                        f"{key} has row-level security but no mapped role "
                        "gets a read policy, and bigquery.admin_principal is "
                        "empty, so no deny-all policy can be written: the "
                        "table would be readable by every principal with "
                        "table access",
                        "set bigquery.admin_principal so the plan can write "
                        "rls_deny_all")
            policies.extend(emitted)
        policies.sort(key=lambda p: (p["dataset"], p["table"], p["name"]))
        return policies

    def policy_entry(self, rel, name, source_roles, filter_sql, confidence,
                     notes, sources, members=None):
        return {"dataset": rel["dataset"], "table": rel["bq_name"],
                "source_table": _key(rel["schema"], rel["name"]),
                "name": bq_types.sanitize_identifier(name)[0],
                "members": list(members or []),
                "source_roles": list(source_roles),
                "filter": filter_sql, "confidence": confidence,
                "notes": list(notes), "source_policies": sources}

    # ---- authorized views

    def build_authorized_views(self):
        bases = {}
        for dep in self.inv.get("view_dependencies", []):
            bases.setdefault(dep["view"], set()).add(dep["base"])
        out, seen = [], set()
        for key in sorted(self.relations):
            rel = self.relations[key]
            if rel["kind"] not in ("view", "matview"):
                continue
            view_ref = f"{rel['dataset']}.{rel['bq_name']}"
            needy = {}
            for role in sorted(self.roles):
                if self.is_superuser(role) or not self.mapped(role):
                    continue
                if "SELECT" not in self.eff[role]["relations"].get(key, set()):
                    continue
                for base in sorted(bases.get(key, ())):
                    brel = self.relations.get(base)
                    if brel is None:
                        continue
                    if "SELECT" in self.eff[role]["relations"].get(base, set()):
                        continue
                    needy.setdefault(base, []).append(role)
                    sig = (view_ref, brel["dataset"])
                    if sig not in seen:
                        seen.add(sig)
                        out.append({"view": view_ref,
                                    "dataset": brel["dataset"]})
            if needy:
                detail = "; ".join(
                    f"{base} (no table SELECT for {', '.join(roles)})"
                    for base, roles in sorted(needy.items()))
                self.finding(
                    "NOTE", "authorized_view", key,
                    f"{key} is authorized on its base datasets so it works "
                    f"for roles that cannot read every base table: {detail}",
                    "nothing to do; this mirrors PostgreSQL view semantics")
            for base in sorted(bases.get(key, ())):
                if base in self.rls_tables:
                    self.finding(
                        "INFO", "view_rls_semantics", key,
                        f"{key} reads {base}, which has row-level security; "
                        "PostgreSQL evaluates a view as its owner (RLS "
                        "bypassed unless security_invoker), while BigQuery "
                        "applies the querying principal's row access "
                        "policies on the base table",
                        "check whether readers of the view expect the "
                        "owner's unfiltered rows")
                if base in self.restricted:
                    self.finding(
                        "INFO", "view_column_semantics", key,
                        f"{key} reads {base}, which has restricted columns; "
                        "PostgreSQL lets view readers see them through the "
                        "owner, while BigQuery enforces the policy tags on "
                        "the querying principal even through an authorized "
                        "view",
                        "grant the tag reader role to view readers that need "
                        "those columns")
        out.sort(key=lambda a: (a["dataset"], a["view"]))
        return out

    # ---- role level findings

    def flag_roles(self, bindings):
        dataset_members = {(b["member"], b["resource"]) for b in bindings
                           if b["scope"] == "dataset"}
        mem_rows = _memberships(self.sec)
        for role in sorted(self.roles):
            entry = self.eff[role]
            memberships = [m for m in mem_rows if m["member"] == role
                           and m["group"] in self.roles]
            broken = [m["group"] for m in memberships
                      if not membership_inherits(m, self.roles[role],
                                                 self.server_major)]
            if broken:
                self.finding(
                    "WARNING", "noinherit_not_flattened", role,
                    f"{role} is a member of {', '.join(sorted(broken))} "
                    "without inheritance (NOINHERIT role or a membership "
                    "granted WITH INHERIT FALSE); on PostgreSQL it uses those "
                    "privileges only after SET ROLE, which BigQuery cannot "
                    "express, so they were not flattened into its principal",
                    "map the group role to its own principal and let people "
                    "switch identities, or grant INHERIT on the source")
            if self.mapped(role) or self.is_superuser(role):
                continue
            items = self.would_receive.get(role, [])
            has_any = bool(entry["relations"] or entry["columns"]
                           or entry["schemas"])
            if not has_any:
                continue
            self.finding(
                "WARNING", "unmapped_role", role,
                f"role {role} has no principal in the principal map; it "
                "receives nothing on BigQuery. It would have received: "
                + ("; ".join(items) if items else "no binding"),
                "add a principal for the role or confirm it is retired")
        for row in self.sec.get("default_privileges", []):
            schema = row.get("schema")
            grantee = row["grantee"]
            subject = f"{schema or '*'}/{grantee}"
            if any(f["code"] == "default_privileges_note"
                   and f["subject"] == subject for f in self.findings):
                continue
            member = self.principals.get(grantee)
            covered = member is not None and any(
                m == member for m, _ in dataset_members)
            where = (f"schema {schema}" if schema else "every schema")
            self.finding(
                "NOTE", "default_privileges_note", subject,
                f"{row['for_role']} grants {row['privilege']} on future "
                f"{row['object_type']}s in {where} to {grantee}; BigQuery has "
                "no default privileges, and only a dataset-level binding "
                "covers tables created later"
                + (f"; {grantee} already holds a dataset-level binding"
                   if covered else
                   f"; {grantee} holds table-level bindings only"),
                "nothing to do" if covered else
                "consider binding_granularity dataset for this role, or "
                "rerun the security plan after adding tables")
        owners = sorted({o for o in self.owners.values() if o})
        if owners:
            self.finding(
                "NOTE", "ownership_not_mapped", "owners",
                f"relation ownership ({', '.join(owners)}) is not mapped; the "
                "identity running the migration owns the datasets",
                "nothing to do")
        for view in sorted(self.sec.get("security_barrier_views", [])):
            self.finding(
                "WARNING", "security_barrier_view", view,
                f"{view} is a security_barrier view; if it implements "
                "conditional column or row visibility, that logic is not "
                "translated into policy tags or row access policies",
                "review the view body and express its rule as a row access "
                "policy or policy tag by hand")

    def flag_translations(self):
        """translation_review (WARNING, blocks apply) for a review-flagged
        predicate that an emitted row policy carries; when the predicate
        reaches only roles without a principal, no policy carries it, so
        the finding is INFO translation_review_unmapped and nobody is sent
        to resolve it."""
        for ref in sorted(self.review_refs):
            item = self.review_refs[ref]
            what = (f"the predicate of policy {item['name']} on {item['key']} "
                    f"could not be translated automatically: "
                    f"{' '.join(item['notes'])}")
            if item["emitted"]:
                self.finding(
                    "WARNING", "translation_review", ref, what,
                    "dispatch the sql-translator agent; apply is blocked "
                    f"until {RESOLUTIONS_FILE} carries a resolution for {ref}")
                continue
            roles = ", ".join(sorted(item["roles"])) or "no role"
            self.finding(
                "INFO", "translation_review_unmapped", ref,
                what + f"; it reaches only roles without a principal "
                f"({roles}), so no BigQuery policy carries it and nothing "
                "blocks apply",
                "nothing to do; if such a role gets a principal, plan again "
                "and the sql-translator agent must resolve the predicate")

    def flag_inventory(self):
        """WARNING inventory_without_columns per readable table that has
        no column rows: its table privileges are mapped, but nothing can
        be said about its columns and its probes select none."""
        for key in sorted(self.readable):
            rel = self.relations.get(key)
            if rel is None or rel["kind"] != "table":
                continue
            if self.columns.get(key) or not self.readable[key]:
                continue
            readers = ", ".join(sorted(self.readable[key]))
            self.finding(
                "WARNING", "inventory_without_columns", key,
                f"the inventory has no column rows for {key}, which "
                f"{readers} can read; the table privileges are mapped, but "
                "column privileges cannot be analyzed and its probes select "
                "no columns",
                "re-run the assess phase (inventory --out "
                "artifacts/inventory.json) with dbcarry v0.2.0 and plan "
                "again")

    def nesting_notes(self):
        notes = []
        for m in _memberships(self.sec):
            member, group = m["member"], m["group"]
            if member not in self.roles or group not in self.roles:
                continue
            mp = self.principals.get(member)
            gp = self.principals.get(group)
            if mp and gp:
                notes.append(
                    f"{member} is a member of {group} on PostgreSQL: this "
                    f"plan grants {mp} the flattened privileges directly. "
                    f"Nesting {mp} inside {gp} in Google Groups would mirror "
                    "the membership, but then remove the duplicated bindings "
                    "by hand.")
            else:
                who = member if not mp else group
                notes.append(
                    f"{member} is a member of {group} on PostgreSQL; {who} "
                    "has no principal, so nothing to nest.")
        return notes

    def effective_view(self):
        out = {}
        for role in sorted(self.eff):
            entry = self.eff[role]
            per_rel = {}
            for key, privs in entry["relations"].items():
                per_rel.setdefault(key, []).extend(sorted(privs))
            for key, cols in entry["columns"].items():
                by_priv = {}
                for col, privs in cols.items():
                    for p in privs:
                        by_priv.setdefault(p, []).append(col)
                for p in sorted(by_priv):
                    per_rel.setdefault(key, []).append(
                        f"{p}({', '.join(sorted(by_priv[p]))})")
            out[role] = {k: sorted(v) for k, v in sorted(per_rel.items())}
        return out

    # ---- assemble

    def build(self):
        tags = self.build_tags()
        policies = self.build_row_policies()
        bindings, _ = self.build_bindings()
        authorized = self.build_authorized_views()
        masking = self.build_masking(tags)
        self.flag_roles(bindings)
        self.flag_translations()
        self.flag_inventory()
        identity_notes = sorted(set(self.identity_notes))
        findings = sorted(
            self.findings,
            key=lambda f: (SEVERITY_RANK[f["severity"]], f["subject"],
                           f["code"], f["message"]))
        return {
            "migration": self.migration,
            "project": self.project,
            "location": self.location,
            "mode": self.mode,
            "taxonomy": {"display_name": f"dbcarry_{self.migration}",
                         "activated": [FGAC]},
            "datasets": dict(sorted(self.datasets.items())),
            "principals": dict(sorted(self.principals.items())),
            "bindings": bindings,
            "policy_tags": tags,
            "row_policies": policies,
            "authorized_views": authorized,
            "identity_notes": identity_notes,
            "nesting_notes": self.nesting_notes(),
            "masking": masking,
            "findings": findings,
            "effective": self.effective_view(),
            "context_tables": dict(sorted(self.context_tables.items())),
        }


def plan_security(security_inv, inventory, bq_cfg, principal_map,
                  resolutions=None):
    """Map the source's security model onto BigQuery controls (spec 7).

    Pure: no backend, no files. Raises SecurityPlanError for a principal
    that is not a typed IAM member or that names every user.
    """
    return _Planner(security_inv, inventory, bq_cfg, principal_map,
                    resolutions).build()


def review_items(plan):
    """Review-flagged source policies for translation-review.json:
    {"schema.table/policy": {"source_sql", "auto_sql", "notes",
                             "context_tables"}}."""
    out = {}
    for pol in plan.get("row_policies", []):
        for src in pol.get("source_policies", []):
            if src.get("confidence") != "review":
                continue
            key = f"{_source_table(plan, pol)}/{src['name']}"
            out.setdefault(key, {
                "source_sql": src.get("using") or "",
                "auto_sql": src.get("sql") or "",
                "notes": list(src.get("notes") or []),
                "context_tables": dict(plan.get("context_tables") or {})})
    return dict(sorted(out.items()))


def _source_table(plan, pol):
    """schema.table of a row policy on the source, exactly as
    translate_policy keys resolutions: the policy's source_table. A plan
    file written before that field existed falls back to the dataset map
    and the BigQuery table name."""
    if pol.get("source_table"):
        return pol["source_table"]
    schema = (plan.get("datasets") or {}).get(pol["dataset"], {}).get(
        "source_schema", pol["dataset"])
    return f"{schema}.{pol['table']}"


# ---------------------------------------------------------------- rendering

def _sh_quote(text):
    return "'" + str(text).replace("'", "'\"'\"'") + "'"


def _member_to_access(member):
    kind, _, value = member.partition(":")
    if kind == "group":
        return {"groupByEmail": value}
    if kind in ("user", "serviceAccount"):
        return {"userByEmail": value}
    if kind == "domain":
        return {"domain": value}
    return {"iamMember": member}


def render_apply_scripts(plan, bq_cfg):
    """Shell and SQL renderings of the plan for hand review. bq-security
    apply performs the same operations through the backend."""
    project = plan.get("project") or bq_cfg.get("project")
    location = str(plan.get("location") or bq_cfg.get("location") or "US")
    dc_location = location.lower()
    migration = plan.get("migration") or bq_cfg.get("migration")
    head = ["#!/usr/bin/env bash",
            f"# dbcarry security plan for migration {migration} "
            f"(project {project}, {plan.get('mode')} mode)",
            "# Rendered from artifacts/security-plan.json for review. "
            "bq-security apply runs",
            "# the same operations through the backend; run this by hand "
            "only as a fallback.",
            "set -euo pipefail", ""]
    out = {}

    iam = list(head)
    project_b = [b for b in plan["bindings"] if b["scope"] == "project"]
    dataset_b = [b for b in plan["bindings"] if b["scope"] == "dataset"]
    table_b = [b for b in plan["bindings"] if b["scope"] == "table"]
    iam.append("# --- project bindings")
    for b in project_b:
        iam.append(f"gcloud projects add-iam-policy-binding "
                   f"{_sh_quote(project)} "
                   f"--member={_sh_quote(b['member'])} "
                   f"--role={_sh_quote(b['role'])} "
                   f"--condition=None   # {b['source_role']}: {b['reason']}")
    iam.append("")
    iam.append("# --- dataset access entries (bq has no add-access verb: show, "
               "edit the access list, update)")
    by_dataset = {}
    for b in dataset_b:
        by_dataset.setdefault(b["resource"], []).append(
            (dict({"role": b["role"]}, **_member_to_access(b["member"])),
             f"{b['source_role']}: {b['reason']}"))
    for av in plan.get("authorized_views", []):
        ds, _, view = av["view"].partition(".")
        by_dataset.setdefault(av["dataset"], []).append(
            ({"view": {"projectId": project, "datasetId": ds,
                       "tableId": view}}, "authorized view"))
    for dataset in sorted(by_dataset):
        iam.append(f"bq --project_id={project} --format=prettyjson show "
                   f"{project}:{dataset} > {dataset}.access.json")
        iam.append(f"# add each entry below to \"access\" in {dataset}.access.json:")
        for entry, why in by_dataset[dataset]:
            iam.append(f"#   {json.dumps(entry)}   # {why}")
        iam.append(f"# bq --project_id={project} update --source "
                   f"{dataset}.access.json {project}:{dataset}")
    iam.append("")
    iam.append("# --- table and view bindings")
    for b in table_b:
        iam.append(f"bq --project_id={_sh_quote(project)} "
                   f"add-iam-policy-binding "
                   f"--member={_sh_quote(b['member'])} "
                   f"--role={_sh_quote(b['role'])} "
                   f"{_sh_quote(project + ':' + b['resource'])}   "
                   f"# {b['source_role']}: {b['reason']}")
    out["30-iam.sh"] = "\n".join(iam) + "\n"

    tags = list(head)
    tax = plan["taxonomy"]
    api = "https://datacatalog.googleapis.com/v1"
    parent = f"projects/{project}/locations/{dc_location}"
    tags.append("# gcloud has no taxonomies create verb; the Data Catalog "
                "REST API creates the taxonomy and its tags.")
    tags.append(f"# activatedPolicyTypes {FGAC} is what makes the tags "
                "enforced rather than descriptive.")
    tags.append('TOKEN="$(gcloud auth print-access-token)"')
    tags.append('AUTH="Authorization: Bearer ${TOKEN}"')
    tags.append("json_name() { python -c 'import json, sys; "
                "print(json.load(sys.stdin)[\"name\"])'; }")
    body = json.dumps({"displayName": tax["display_name"],
                       "activatedPolicyTypes": list(tax["activated"])})
    tags.append(f'TAXONOMY="$(curl -sS -X POST -H "${{AUTH}}" '
                f'-H "Content-Type: application/json" -d {_sh_quote(body)} '
                f'"{api}/{parent}/taxonomies" | json_name)"')
    tags.append('TAXONOMY_ID="${TAXONOMY##*/}"')
    tags.append("")
    for tag in plan["policy_tags"]:
        var = f"TAG_{tag['name']}"
        body = json.dumps({"displayName": tag["name"],
                           "description": tag["description"]})
        tags.append(f"# tag {tag['name']}: "
                    f"{', '.join(tag['source_columns'])}")
        tags.append(f'{var}="$(curl -sS -X POST -H "${{AUTH}}" '
                    f'-H "Content-Type: application/json" -d {_sh_quote(body)} '
                    f'"{api}/${{TAXONOMY}}/policyTags" | json_name)"')
        for reader in tag["readers"]:
            tags.append(
                f"gcloud data-catalog taxonomies policy-tags "
                f"add-iam-policy-binding \"${{{var}##*/}}\" "
                f"--taxonomy=\"${{TAXONOMY_ID}}\" --location={dc_location} "
                f"--project={_sh_quote(project)} "
                f"--member={_sh_quote(reader['member'])} "
                f"--role={ROLE_FGR}   # {reader['source_role']}")
        by_table = {}
        for col in tag["columns"]:
            by_table.setdefault((col["dataset"], col["table"]), []).append(
                col["column"])
        for (dataset, table), cols in sorted(by_table.items()):
            tags.append(f"# attach to {dataset}.{table} columns "
                        f"{', '.join(cols)}: bq --project_id={project} "
                        f"--format=prettyjson show --schema "
                        f"{project}:{dataset}.{table} > {table}.schema.json, "
                        f"set \"policyTags\": {{\"names\": [\"${{{var}}}\"]}} "
                        f"on each column, then bq --project_id={project} "
                        f"update {project}:{dataset}.{table} "
                        f"{table}.schema.json")
        tags.append("")
    if not plan["policy_tags"]:
        tags.append("# no restricted columns: no policy tags are planned")
    out["40-policy-tags.sh"] = "\n".join(tags) + "\n"

    sql = [f"-- dbcarry row access policies for migration {migration} "
           f"(project {project})",
           "-- Rendered from artifacts/security-plan.json. Policies marked "
           "REVIEW are commented out:",
           "-- apply refuses them until translation-resolutions.json "
           "carries a resolution.", ""]
    for pol in plan["row_policies"]:
        ref = bq_types.qualified(project, pol["dataset"], pol["table"])
        grantees = ", ".join(
            '"' + m.replace("\\", "\\\\").replace('"', '\\"') + '"'
            for m in pol["members"])
        stmt = (f"CREATE OR REPLACE ROW ACCESS POLICY {pol['name']} ON {ref} "
                f"GRANT TO ({grantees}) FILTER USING ({pol['filter']});")
        sources = ", ".join(s["name"] for s in pol["source_policies"]) or "none"
        sql.append(f"-- {pol['dataset']}.{pol['table']} / {pol['name']}: "
                   f"source table {_source_table(plan, pol)}; "
                   f"roles {', '.join(pol['source_roles']) or 'admin'}; "
                   f"source policies {sources}; confidence {pol['confidence']}")
        for note in pol["notes"]:
            sql.append(f"--   note: {_normalize_ws(note)}")
        if pol["confidence"] not in APPLIABLE_CONFIDENCES:
            sql.append("-- REVIEW: not applied until resolved")
            sql.append("-- " + stmt)
        else:
            sql.append(stmt)
        sql.append("")
    if not plan["row_policies"]:
        sql.append("-- no row access policies are planned")
    out["50-row-policies.sql"] = "\n".join(sql) + "\n"

    if plan.get("masking"):
        docs = []
        for m in plan["masking"]:
            docs.append({
                "dataPolicyId": m["data_policy_id"],
                "dataPolicyType": "DATA_MASKING_POLICY",
                "policyTag": f"<resource name of tag {m['tag']} after apply>",
                "dataMaskingPolicy": {"predefinedExpression": m["rule"]},
                "bindings": [{"role": ROLE_MASKED_READER,
                              "members": list(m["masked_readers"])}],
                "note": "request body for bigquerydatapolicy.googleapis.com "
                        "dataPolicies.create; dbcarry writes it and does "
                        "not execute it (no CLI surface)"})
        out["60-masking-requests.json"] = json.dumps(docs, indent=2) + "\n"

    notes = [f"# Identity notes for migration {migration}", "",
             "This file is documentation only and is never executed.", "",
             "## Role memberships", ""]
    if plan.get("nesting_notes"):
        notes.extend(f"- {n}" for n in plan["nesting_notes"])
    else:
        notes.append("- no role memberships on the source")
    notes.extend(["", "## Principals", ""])
    for role, member in sorted(plan["principals"].items()):
        notes.append(f"- {role}: {member}")
    unmapped = sorted(r for r in plan.get("effective", {})
                      if r not in plan["principals"])
    if unmapped:
        notes.append(f"- unmapped: {', '.join(unmapped)}")
    notes.extend(["", "## Identity predicates", ""])
    if plan.get("identity_notes"):
        notes.extend(f"- {n}" for n in plan["identity_notes"])
    else:
        notes.append("- no policy compares a column with the caller's "
                     "identity")
    notes.extend([
        "", "## Probes", "",
        "- Live mode probes impersonate the probe_service_account of each "
        "role in the principal map; add the service account to the role's "
        "group so it holds exactly the role's access.",
        "- Emulated mode probes run inside the emulator and prove pipeline "
        "logic, not BigQuery's behavior."])
    out["70-identity-notes.md"] = "\n".join(notes) + "\n"
    return out


def _md_cell(value):
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(v) for v in value)
    return _normalize_ws(value).replace("|", "\\|") or " "


def _md_table(headers, rows):
    if not rows:
        return ["(none)", ""]
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(_md_cell(c) for c in row) + " |")
    lines.append("")
    return lines


def render_plan_markdown(plan):
    counts = {}
    for f in plan["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    lines = [f"# Security plan: {plan.get('migration')}", "",
             f"Project {plan.get('project')}, location "
             f"{plan.get('location')}, mode {plan.get('mode')}. "
             f"{len(plan['principals'])} mapped principals, "
             f"{len(plan['bindings'])} bindings, "
             f"{len(plan['policy_tags'])} policy tags, "
             f"{len(plan['row_policies'])} row access policies, "
             f"{len(plan['authorized_views'])} authorized views. Findings: "
             + ", ".join(f"{counts.get(s, 0)} {s}" for s in SEVERITY_RANK)
             + ".", "",
             f"Taxonomy {plan['taxonomy']['display_name']} activated for "
             f"{', '.join(plan['taxonomy']['activated'])}. Datasets: "
             + ", ".join(f"{d} (from schema {v['source_schema']})"
                         for d, v in plan["datasets"].items()) + ".", ""]
    lines += ["## Principals", ""]
    rows = []
    for role in sorted(plan.get("effective", {})):
        member = plan["principals"].get(role, "(unmapped)")
        rows.append([role, member])
    lines += _md_table(["PostgreSQL role", "BigQuery principal"], rows)
    lines += ["## Bindings", ""]
    lines += _md_table(
        ["scope", "resource", "role", "member", "source role", "reason"],
        [[b["scope"], b["resource"], b["role"], b["member"],
          b["source_role"], b["reason"]] for b in plan["bindings"]])
    lines += ["## Policy tags", ""]
    lines += _md_table(
        ["tag", "columns", "readers"],
        [[t["name"], t["source_columns"],
          [f"{r['member']} ({r['source_role']})" for r in t["readers"]]]
         for t in plan["policy_tags"]])
    lines += ["## Row access policies", ""]
    lines += _md_table(
        ["table", "policy", "members", "filter", "confidence",
         "source policies", "notes"],
        [[f"{p['dataset']}.{p['table']}", p["name"], p["members"],
          p["filter"], p["confidence"],
          [f"{s['name']} (via {s.get('via', '')})"
           for s in p["source_policies"]], p["notes"]]
         for p in plan["row_policies"]])
    lines += ["## Authorized views", ""]
    lines += _md_table(["view", "authorized on dataset"],
                       [[a["view"], a["dataset"]]
                        for a in plan["authorized_views"]])
    if plan.get("masking"):
        lines += ["## Masking requests", ""]
        lines += _md_table(["tag", "data policy", "rule", "masked readers"],
                           [[m["tag"], m["data_policy_id"], m["rule"],
                             m["masked_readers"]] for m in plan["masking"]])
    lines += ["## Findings", ""]
    lines += _md_table(["severity", "code", "subject", "message", "action"],
                       [[f["severity"], f["code"], f["subject"], f["message"],
                         f["action"]] for f in plan["findings"]])
    lines += ["## Identity notes", ""]
    notes = list(plan.get("nesting_notes", [])) + list(
        plan.get("identity_notes", []))
    lines += [f"- {n}" for n in notes] or ["(none)"]
    lines.append("")
    return "\n".join(lines)


def principal_map_template(security_inv):
    """The security/principal-map.yaml template of spec section 4."""
    roles = sorted(security_inv.get("roles", []), key=lambda r: r["name"])
    listed = [r["name"] for r in roles
              if not r["name"].startswith("pg_") and not r.get("superuser")]
    superusers = [r["name"] for r in roles if r.get("superuser")]
    lines = [
        "# One BigQuery principal per PostgreSQL role. Types: user:, group:, "
        "serviceAccount:.",
        "# Recommended: one Google Group per role. Leave empty to leave the "
        "role unmapped",
        "# (the plan will flag it; BigQuery denies by default).",
        "# probe_service_account is optional: a service account the verifier "
        "impersonates",
        "# in live mode to run the probe queries with that role's access.",
        "roles:"]
    for name in listed:
        key = name if _YAML_BARE_KEY.match(name) else json.dumps(name)
        lines += [f"  {key}:", '    principal: ""',
                  '    probe_service_account: ""']
    if superusers:
        lines += [
            f"# Superusers on the source, not listed above: "
            f"{', '.join(superusers)}.",
            "# Add an entry for a superuser only when a bypass principal is "
            "wanted: the plan",
            "# gives it dataOwner on every dataset, every policy tag, and a "
            "FILTER USING (TRUE)",
            "# row policy on every RLS table."]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- apply

def _existing_taxonomy(backend, display_name):
    for tax in backend.list_taxonomies():
        if tax.get("displayName") == display_name:
            return tax["name"]
    return None


def _table_field(fields, column):
    for f in fields:
        if str(f.get("name", "")).lower() == column.lower():
            return f
    return None


APPLIABLE_CONFIDENCES = ("auto", "resolved")
KNOWN_CONFIDENCES = APPLIABLE_CONFIDENCES + ("review",)


def check_plan(plan):
    """Raise SecurityPlanError when a plan artifact carries a row policy
    confidence outside auto, resolved, review: apply and the renderers
    trust only those two spellings that mean applicable."""
    for p in plan.get("row_policies", []):
        c = p.get("confidence")
        if c not in KNOWN_CONFIDENCES:
            raise SecurityPlanError(
                f"row policy {p.get('name')} on {p.get('dataset')}."
                f"{p.get('table')} has confidence {c!r}; the plan accepts "
                f"only {', '.join(KNOWN_CONFIDENCES)}; re-run bq-security "
                "plan")


def refuse_open_tables(plan):
    """Raise SecurityPlanError when the plan leaves an RLS table without
    any row access policy (finding rls_deny_all_unassigned): a table with
    no policy is open to every reader, which apply must not create."""
    open_tables = [f["subject"] for f in plan.get("findings", [])
                   if f.get("code") == "rls_deny_all_unassigned"]
    if open_tables:
        raise SecurityPlanError(
            "refusing to apply: rls_deny_all_unassigned on "
            f"{', '.join(open_tables)} (a row-level security table would "
            "get no row access policy and be open to every reader); set "
            "bigquery.admin_principal or map the roles, then re-run "
            "bq-security plan")


def refuse_unresolved(plan):
    """Raise SecurityPlanError naming every row policy whose confidence is
    not one of the two that mean applicable (auto, resolved): review, and
    any other spelling, blocks apply."""
    review = [p for p in plan.get("row_policies", [])
              if p.get("confidence") not in APPLIABLE_CONFIDENCES]
    if not review:
        return
    items = []
    for p in review:
        refs = [f"{_source_table(plan, p)}/{s['name']}"
                for s in p.get("source_policies", [])
                if s.get("confidence") == "review"]
        items.append(f"{p['name']} on {p['dataset']}.{p['table']} "
                     f"(confidence {p.get('confidence')!r}; source: "
                     f"{', '.join(refs) or 'unknown'})")
    raise SecurityPlanError(
        f"refusing to apply: {len(review)} row access policies need review "
        "by the sql-translator agent: " + "; ".join(items))


def apply_plan(plan, backend, log=None):
    """Apply the plan through the backend in a fixed order.

    taxonomy, policy tags, tag readers, project bindings, dataset access
    entries (bindings and authorized views), table bindings, column tag
    attachment through the table schema, row access policies. Re-running
    is safe: existing taxonomies and tags are reused by display name and
    the backends ignore bindings that already exist.

    Refuses (SecurityPlanError, before touching the backend) when any row
    access policy has confidence "review". Returns {"taxonomy", "tags",
    "ops"} and records the same under plan["applied"].
    """
    refuse_unresolved(plan)
    refuse_open_tables(plan)
    ops = 0
    if log:
        log.record("security_apply_start", migration=plan.get("migration"),
                   bindings=len(plan.get("bindings", [])),
                   tags=len(plan.get("policy_tags", [])),
                   row_policies=len(plan.get("row_policies", [])))
    applied = {"taxonomy": None, "tags": {}}
    tags = plan.get("policy_tags", [])
    if tags:
        display = plan["taxonomy"]["display_name"]
        taxonomy = _existing_taxonomy(backend, display)
        if taxonomy is None:
            taxonomy = backend.create_taxonomy(
                display, list(plan["taxonomy"]["activated"]))
            ops += 1
        applied["taxonomy"] = taxonomy
        existing = {t["displayName"]: t["name"]
                    for t in backend.list_policy_tags(taxonomy)}
        for tag in tags:
            resource = existing.get(tag["name"])
            if resource is None:
                resource = backend.create_policy_tag(
                    taxonomy, tag["name"], tag.get("description", ""))
                ops += 1
            applied["tags"][tag["name"]] = resource
        for tag in tags:
            for reader in tag["readers"]:
                backend.add_policy_tag_binding(
                    applied["tags"][tag["name"]], ROLE_FGR, reader["member"])
                ops += 1
    for b in plan.get("bindings", []):
        if b["scope"] == "project":
            backend.add_project_binding(b["role"], b["member"])
            ops += 1
    for b in plan.get("bindings", []):
        if b["scope"] == "dataset":
            backend.add_dataset_access(
                b["resource"], {"role": b["role"], "member": b["member"]})
            ops += 1
    for av in plan.get("authorized_views", []):
        backend.add_dataset_access(av["dataset"], {"view": av["view"]})
        ops += 1
    for b in plan.get("bindings", []):
        if b["scope"] == "table":
            dataset, _, table = b["resource"].partition(".")
            backend.add_table_binding(dataset, table, b["role"], b["member"])
            ops += 1
    by_table = {}
    for tag in tags:
        for col in tag["columns"]:
            by_table.setdefault((col["dataset"], col["table"]), []).append(
                (col["column"], applied["tags"][tag["name"]]))
    for (dataset, table), cols in sorted(by_table.items()):
        fields = backend.get_table_schema(dataset, table)
        for column, resource in cols:
            field = _table_field(fields, column)
            if field is None:
                raise SecurityPlanError(
                    f"column {column} not found in {dataset}.{table}; run "
                    "bq-schema apply before bq-security apply")
            field["policyTags"] = {"names": [resource]}
        backend.update_table_schema(dataset, table, fields)
        ops += 1
    for pol in plan.get("row_policies", []):
        backend.create_row_policy(pol["dataset"], pol["table"], pol["name"],
                                  list(pol["members"]), pol["filter"])
        ops += 1
    plan["applied"] = {"taxonomy": applied["taxonomy"],
                       "tags": dict(applied["tags"])}
    if log:
        log.record("security_apply_done", ops=ops,
                   taxonomy=applied["taxonomy"],
                   tags=sorted(applied["tags"]))
    return {"taxonomy": applied["taxonomy"], "tags": dict(applied["tags"]),
            "ops": ops}


# ---------------------------------------------------------------- verify

def _member_key(member):
    kind, _, value = str(member).partition(":")
    if kind in ("user", "serviceAccount"):
        kind = "userByEmail"
    return (kind, value.lower())


def _has_binding(rows, role, member):
    want = _member_key(member)
    for r in rows:
        if r.get("role") == role and _member_key(r.get("member", "")) == want:
            return True
    return False


def _tag_suffix(name):
    """A policy tag resource name without its project segment, so a name
    Data Catalog reports with the project number equals the same tag as
    a BigQuery table schema reports it with the project id. Anything
    that is not a full tag name is returned unchanged."""
    m = _TAG_NAME_RE.match(str(name or ""))
    if not m:
        return str(name or "")
    location, taxonomy, tag = m.groups()
    return f"locations/{location.lower()}/taxonomies/{taxonomy}/policyTags/{tag}"


class _ReadBack:
    """Memoized read-back calls; a backend error becomes a string actual."""

    def __init__(self, backend):
        self.backend = backend
        self.cache = {}

    def get(self, name, fn, *args):
        key = (name,) + args
        if key not in self.cache:
            try:
                self.cache[key] = fn(*args)
            except bq_backend.BackendError as exc:
                self.cache[key] = f"error: {exc}"
        return self.cache[key]


def _is_everyone(member):
    kind, _, value = str(member or "").partition(":")
    forbidden = {m.lower() for m in bq_backend.FORBIDDEN_MEMBERS}
    return str(member or "").lower() in forbidden or value.lower() in forbidden


def _verify_extras(plan, backend, rb, check):
    """Bindings the plan does not name, read back from the target.

    Tables and datasets the pipeline created are pipeline-owned, so a
    data read role there for an unplanned member fails with expected
    "absent" (table_binding_extra, dataset_access_extra), and so does an
    authorized view the plan does not list (authorized_view_extra). Two
    dataset entries are not extras: the three project special groups
    that BigQuery adds to every new dataset, and, in live mode only, a
    dataOwner entry for a user or service account, which is the identity
    that created the dataset (reported as a passing
    dataset_owner_identity check so the validator sees it; in emulated
    mode nothing creates such an entry, so it is an extra). The project
    IAM policy is not pipeline-owned: only an everyone-principal there
    (allUsers, allAuthenticatedUsers) fails, as project_binding_extra.
    """
    planned = set()
    for b in plan.get("bindings", []):
        planned.add((b["scope"], b["resource"], b["role"],
                     _member_key(b["member"])))
    planned_views = {(av["dataset"], av["view"])
                     for av in plan.get("authorized_views", [])}
    live = (plan.get("mode") or "emulated") == "live"
    special = {f"specialgroup:{g.lower()}" for g in
               bq_backend.PROJECT_SPECIAL_GROUPS}

    rows = rb.get("project", backend.get_project_bindings)
    for r in ([] if isinstance(rows, str) else rows):
        if _is_everyone(r.get("member")):
            check(f"project_binding_extra:{r.get('role')}:{r.get('member')}",
                  "absent", "present", False)

    datasets = sorted(set(plan.get("datasets", {}))
                      | {b["resource"] for b in plan.get("bindings", [])
                         if b["scope"] == "dataset"}
                      | {av["dataset"] for av in plan.get("authorized_views", [])})
    for dataset in datasets:
        rows = rb.get("dataset", backend.get_dataset_access, dataset)
        for e in ([] if isinstance(rows, str) else rows):
            if "view" in e:
                if (dataset, e["view"]) not in planned_views:
                    check(f"authorized_view_extra:{dataset}:{e['view']}",
                          "absent", "present", False)
                continue
            role, member = e.get("role"), e.get("member", "")
            if role not in bq_backend.DATA_READ_ROLES:
                continue
            if ("dataset", dataset, role, _member_key(member)) in planned:
                continue
            kind, _, value = str(member).partition(":")
            if _is_everyone(member):
                pass
            elif f"{kind.lower()}:{value.lower()}" in special:
                continue
            elif live and role == ROLE_OWNER and \
                    _member_key(member)[0] == "userByEmail":
                check(f"dataset_owner_identity:{dataset}:{member}",
                      "migration identity (not planned)", "present", True)
                continue
            check(f"dataset_access_extra:{dataset}:{role}:{member}",
                  "absent", "present", False)
        tables = rb.get("tables", backend.list_tables, dataset)
        for t in ([] if isinstance(tables, str) else tables):
            table = t["name"] if isinstance(t, dict) else str(t)
            rows = rb.get("table", backend.get_table_bindings, dataset, table)
            for r in ([] if isinstance(rows, str) else rows):
                role, member = r.get("role"), r.get("member", "")
                if role not in bq_backend.DATA_READ_ROLES:
                    continue
                resource = f"{dataset}.{table}"
                if ("table", resource, role, _member_key(member)) in planned:
                    continue
                check(f"table_binding_extra:{resource}:{role}:{member}",
                      "absent", "present", False)


def verify_plan(plan, backend):
    """Read every planned control back through the backend.

    Returns {"checks": [{"name", "expected", "actual", "pass"}],
             "enforcement_active": bool, "pass": bool}. Existence is never
    taken from plan["applied"]; taxonomies and tags are found by display
    name. Tag resource names are compared without their project segment
    (Data Catalog may report the project number where BigQuery reports
    the id). Besides presence, the pipeline-owned controls are checked
    for extras: a row access policy on a planned table that the plan does
    not name (row_policy_extra:<dataset>.<table>/<name>) and a
    fine-grained reader on a planned tag that the plan does not list
    (tag_reader_extra:<tag>:<member>) fail with expected "absent", since
    either can widen access. pass requires every check to pass and, when
    tags are planned, the taxonomy to be activated for
    FINE_GRAINED_ACCESS_CONTROL.
    """
    checks = []
    rb = _ReadBack(backend)

    def check(name, expected, actual, ok):
        checks.append({"name": name, "expected": expected, "actual": actual,
                       "pass": bool(ok)})

    def presence(name, rows, role, member):
        if isinstance(rows, str):
            check(name, "present", rows, False)
        else:
            ok = _has_binding(rows, role, member)
            check(name, "present", "present" if ok else "missing", ok)

    for b in plan.get("bindings", []):
        if b["scope"] == "project":
            rows = rb.get("project", backend.get_project_bindings)
            presence(f"project_binding:{b['role']}:{b['member']}", rows,
                     b["role"], b["member"])
        elif b["scope"] == "dataset":
            rows = rb.get("dataset", backend.get_dataset_access, b["resource"])
            presence(f"dataset_access:{b['resource']}:{b['role']}:"
                     f"{b['member']}", rows, b["role"], b["member"])
        else:
            dataset, _, table = b["resource"].partition(".")
            rows = rb.get("table", backend.get_table_bindings, dataset, table)
            presence(f"table_binding:{b['resource']}:{b['role']}:"
                     f"{b['member']}", rows, b["role"], b["member"])
    for av in plan.get("authorized_views", []):
        rows = rb.get("dataset", backend.get_dataset_access, av["dataset"])
        name = f"authorized_view:{av['dataset']}:{av['view']}"
        if isinstance(rows, str):
            check(name, "present", rows, False)
        else:
            ok = any(e.get("view") == av["view"] for e in rows)
            check(name, "present", "present" if ok else "missing", ok)
    _verify_extras(plan, backend, rb, check)

    enforcement_active = True
    tags = plan.get("policy_tags", [])
    if tags:
        display = plan["taxonomy"]["display_name"]
        try:
            taxonomy = _existing_taxonomy(backend, display)
        except bq_backend.BackendError as exc:
            taxonomy = None
            check("taxonomy", display, f"error: {exc}", False)
        else:
            check("taxonomy", display, taxonomy or "missing",
                  taxonomy is not None)
        tag_names = {}
        if taxonomy is None:
            enforcement_active = False
            check("taxonomy_enforcement", FGAC, "missing", False)
        else:
            desc = rb.get("taxonomy", backend.describe_taxonomy, taxonomy)
            if isinstance(desc, str):
                enforcement_active = False
                check("taxonomy_enforcement", FGAC, desc, False)
            else:
                activated = list(desc.get("activatedPolicyTypes") or [])
                enforcement_active = FGAC in activated
                check("taxonomy_enforcement", FGAC,
                      ", ".join(activated) or "none", enforcement_active)
            listed = rb.get("tags", backend.list_policy_tags, taxonomy)
            if not isinstance(listed, str):
                tag_names = {t["displayName"]: t["name"] for t in listed}
        for tag in tags:
            resource = tag_names.get(tag["name"])
            check(f"policy_tag:{tag['name']}", "present",
                  "present" if resource else "missing", resource is not None)
            recorded = (plan.get("applied") or {}).get("tags", {}).get(
                tag["name"])
            if resource and recorded and \
                    _tag_suffix(recorded) != _tag_suffix(resource):
                check(f"tag_resource:{tag['name']}", recorded, resource, False)
            planned_readers = {_member_key(r["member"])
                               for r in tag["readers"]}
            for reader in tag["readers"]:
                name = f"tag_reader:{tag['name']}:{reader['member']}"
                if resource is None:
                    check(name, "present", "missing", False)
                    continue
                rows = rb.get("tag_bindings", backend.get_policy_tag_bindings,
                              resource)
                presence(name, rows, ROLE_FGR, reader["member"])
            if resource is not None:
                rows = rb.get("tag_bindings", backend.get_policy_tag_bindings,
                              resource)
                for r in ([] if isinstance(rows, str) else rows):
                    if r.get("role") != ROLE_FGR or \
                            _member_key(r.get("member", "")) in planned_readers:
                        continue
                    check(f"tag_reader_extra:{tag['name']}:{r.get('member')}",
                          "absent", "present", False)
            for col in tag["columns"]:
                name = f"column_tag:{col['dataset']}.{col['table']}.{col['column']}"
                fields = rb.get("schema", backend.get_table_schema,
                                col["dataset"], col["table"])
                expected = _tag_suffix(resource) if resource else "<tag missing>"
                if isinstance(fields, str):
                    check(name, expected, fields, False)
                    continue
                field = _table_field(fields, col["column"])
                if field is None:
                    check(name, expected, "column missing", False)
                    continue
                names = list((field.get("policyTags") or {}).get("names") or [])
                check(name, expected, ", ".join(names) or "none",
                      resource is not None
                      and _tag_suffix(resource) in {_tag_suffix(n)
                                                    for n in names})

    for pol in plan.get("row_policies", []):
        name = f"row_policy:{pol['dataset']}.{pol['table']}/{pol['name']}"
        expected = (f"GRANT TO ({', '.join(sorted(pol['members']))}) "
                    f"FILTER USING ({_normalize_ws(pol['filter'])})")
        rows = rb.get("policies", backend.list_row_policies, pol["dataset"],
                      pol["table"])
        if isinstance(rows, str):
            check(name, expected, rows, False)
            continue
        found = next((r for r in rows if r.get("name") == pol["name"]), None)
        if found is None:
            check(name, expected, "missing", False)
            continue
        actual = (f"GRANT TO ({', '.join(sorted(found.get('members') or []))}) "
                  f"FILTER USING ({_normalize_ws(found.get('filter'))})")
        ok = (set(found.get("members") or []) == set(pol["members"])
              and _normalize_ws(found.get("filter"))
              == _normalize_ws(pol["filter"]))
        check(name, expected, actual, ok)
    # row policies on a planned table are pipeline-owned: any the plan
    # does not name is an extra that may grant rows to someone else
    planned = {}
    for pol in plan.get("row_policies", []):
        planned.setdefault((pol["dataset"], pol["table"]), set()).add(
            pol["name"])
    for (dataset, table), names in sorted(planned.items()):
        rows = rb.get("policies", backend.list_row_policies, dataset, table)
        if isinstance(rows, str):
            continue
        for r in rows:
            if r.get("name") in names:
                continue
            actual = (f"GRANT TO ({', '.join(sorted(r.get('members') or []))}) "
                      f"FILTER USING ({_normalize_ws(r.get('filter'))})")
            check(f"row_policy_extra:{dataset}.{table}/{r.get('name')}",
                  "absent", actual, False)

    checks.sort(key=lambda c: c["name"])
    return {"checks": checks, "enforcement_active": enforcement_active,
            "pass": all(c["pass"] for c in checks) and enforcement_active}


# ---------------------------------------------------------------- probes

def _expected(status, sql=None, row_count=None, note=""):
    return {"status": status, "row_count_sql_pg": sql, "row_count": row_count,
            "note": note}


def _plan_read_grants(plan):
    """{member: {(scope, resource): iam role}} for the data read roles."""
    out = {}
    for b in plan.get("bindings", []):
        if b["role"] in bq_backend.DATA_READ_ROLES:
            out.setdefault(b["member"], {})[
                (b["scope"], b["resource"])] = b["role"]
    return out


def _plan_grant(grants, member, project, dataset, table):
    """(scope, resource, iam role) through which member reads
    dataset.table on the target, the narrowest scope first, or None."""
    mine = grants.get(member, {})
    for scope, resource in (("table", f"{dataset}.{table}"),
                            ("dataset", dataset), ("project", project)):
        role = mine.get((scope, resource))
        if role:
            return scope, resource, role
    return None


def _widening_codes(plan, role, member, key, rel):
    """The plan findings that explain why member reads key on the target
    although role cannot on the source."""
    subjects = {"editor_widens": f"{key}/{role}",
                "widened_by_granularity": f"{rel['dataset']}/{member}",
                "schema_create_widens": f"{rel['schema']}/{role}",
                "superuser_mapped": role,
                "principal_shared": member}
    hits = []
    for f in plan.get("findings", []):
        code = f.get("code")
        if code in WIDENING_CODES and f.get("subject") == subjects.get(code) \
                and code not in hits:
            hits.append(code)
    return hits


IDENTITY_PROBE_NOTE = ("identity predicate: the PostgreSQL count depends on "
                       "the role name and the BigQuery count on the "
                       "principal's email, so the counts are reported and "
                       "not compared")


def _row_expectation(member, table_sql, is_rls, table_policies):
    """Expected status and PostgreSQL count query for a row_count probe of
    a table the role reads on the source.

    The status is always ok. On an RLS table the plan's row policies
    naming the member decide: none naming the member means zero rows
    (also when the plan writes no policy for the table at all: the
    member holds no permissive source policy, so zero is the source
    truth and a table left open fails its probes), a TRUE filter means
    the whole table, and otherwise the ORIGINAL source
    predicates of the policies are combined for the PostgreSQL count.
    That holds for resolved and review predicates too: the resolution
    changes the target filter, and the source predicate stays the ground
    truth, which the note says. Identity predicates cannot be compared
    across engines, so their count is reported and not compared.
    """
    if not is_rls:
        return _expected("ok", table_sql)
    mine = [p for p in table_policies if member in (p.get("members") or [])]
    if not mine:
        return _expected(
            "ok", None, 0,
            "RLS table with no policy naming the principal: BigQuery "
            "returns no rows, as PostgreSQL does")
    parts, notes = [], []
    for pol in mine:
        literal = _normalize_ws(pol.get("filter")).strip("() ").upper()
        if literal == "TRUE":
            return _expected("ok", table_sql)
        if literal == "FALSE":
            continue
        sources = pol.get("source_policies") or []
        if any("SESSION_USER()" in (s.get("sql") or "") for s in sources):
            return _expected("ok", None, None, IDENTITY_PROBE_NOTE)
        parts.append(combine_predicates(
            [s.get("using") or "" for s in sources
             if s.get("permissive", True)],
            [s.get("using") or "" for s in sources
             if not s.get("permissive", True)]))
        for s in sources:
            if s.get("confidence") in ("resolved", "review"):
                notes.append(
                    f"policy {s['name']} is {s['confidence']} on the target "
                    f"({s.get('sql')}); its source predicate ({s.get('using')}) "
                    "is the ground truth for the expected count")
    parts = [p for p in parts if p]
    if not parts:
        return _expected(
            "ok", None, 0,
            "every policy naming the principal is FILTER USING (FALSE): "
            "no rows")
    where = parts[0] if len(parts) == 1 else " OR ".join(
        _paren(p) for p in parts)
    if where.strip("() ").lower() == "true":
        return _expected("ok", table_sql, note="; ".join(notes))
    return _expected("ok", f"{table_sql} WHERE {where}",
                     note="; ".join(notes))


def probe_set(plan, security_inv, inventory, principal_map, bq_cfg):
    """Probes for every mapped role (emulated) or every mapped role with a
    probe service account (live). Views are not probed.

    The expected status follows the plan, the expected count follows the
    source. Per table: table_denied when the plan grants the principal no
    data read role on the table, its dataset, or the project; otherwise a
    row_count probe whose PostgreSQL count query comes from the source
    (_row_expectation). When the role cannot read the table on the source
    but the plan grants its principal read access (editor_widens,
    widened_by_granularity, schema_create_widens, superuser_mapped, or a
    principal_shared with another role), the probe expects ok with no
    count and a note naming those findings, and no column_denied probe is
    emitted for that table. Per restricted column: column_allowed when
    the principal is a reader of the column's tag in the plan (through
    any of its roles), column_denied otherwise.
    """
    _require_columns(inventory)
    mode = bq_cfg.get("mode") or "emulated"
    eff = effective_privileges(security_inv,
                               server_version=_inventory_version(inventory))
    readable = readable_columns(eff, inventory)
    restricted = restricted_columns(readable, inventory)
    relations = relation_index(inventory, bq_cfg)
    cols_by_table = columns_index(inventory)
    rls_tables = {_key(r["schema"], r["relation"]) for r in
                  security_inv.get("rls", []) if r.get("enabled")}
    policies_by_table = {}
    for p in plan.get("row_policies", []):
        policies_by_table.setdefault((p["dataset"], p["table"]), []).append(p)
    tag_readers = {}
    for tag in plan.get("policy_tags", []):
        members = {r["member"] for r in tag.get("readers", [])}
        for col in tag.get("columns", []):
            tag_readers[(col["dataset"], col["table"], col["column"])] = members
    grants = _plan_read_grants(plan)
    project = plan.get("project") or bq_cfg.get("project")
    roles = {r["name"]: r for r in security_inv.get("roles", [])}
    probes = []
    for role, entry in sorted((principal_map or {}).get("roles", {}).items()):
        principal = canonical_principal((entry or {}).get("principal") or "")
        probe_sa = str((entry or {}).get("probe_service_account") or "")
        if not principal or role not in roles:
            continue
        if mode == "live" and not probe_sa:
            continue
        superuser = bool(eff[role]["superuser"])

        def add(kind, key, columns, expected):
            rel = relations[key]
            probes.append({"kind": kind, "principal": principal,
                           "probe_service_account": probe_sa,
                           "source_role": role, "dataset": rel["dataset"],
                           "table": rel["bq_name"], "columns": list(columns),
                           "expected": expected})

        for key in sorted(k for k, r in relations.items()
                          if r["kind"] == "table"):
            rel = relations[key]
            names = [c["name"] for c in cols_by_table.get(key, [])]
            if superuser:
                source_read, mine = True, set(names)
            else:
                source_read = role in readable.get(key, {})
                mine = readable.get(key, {}).get(role, set())
            grant = _plan_grant(grants, principal, project, rel["dataset"],
                                rel["bq_name"])
            if grant is None:
                note = ""
                if source_read:
                    note = (f"{role} reads {key} on the source but the plan "
                            f"grants {principal} no data read role on it")
                add("table_denied", key, [], _expected("denied", note=note))
                continue
            table_sql = (f"SELECT count(*) FROM "
                         f"{_quote_pg(rel['schema'], rel['name'])}")
            blocked = {col for col in restricted.get(key, {})
                       if principal not in tag_readers.get(
                           (rel["dataset"], rel["bq_name"], col), set())}
            widened = not source_read
            if widened:
                scope, resource, iam_role = grant
                codes = _widening_codes(plan, role, principal, key, rel)
                ordered = [c for c in names if c not in blocked]
                expected = _expected(
                    "ok", None, None,
                    f"{role} cannot read {key} on the source, but the plan "
                    f"grants {principal} {iam_role.split('.')[-1]} on {scope} "
                    f"{resource} ({', '.join(codes) or 'see the plan'}); the "
                    "BigQuery count is reported and not compared")
            else:
                ordered = [c for c in names if c in mine and c not in blocked]
                expected = _row_expectation(
                    principal, table_sql, key in rls_tables,
                    policies_by_table.get((rel["dataset"], rel["bq_name"]), []))
            skipped = []
            for col in restricted.get(key, {}):
                if col not in blocked:
                    add("column_allowed", key, [col], copy.deepcopy(expected))
                elif widened:
                    skipped.append(col)
                else:
                    add("column_denied", key, [col], _expected("denied"))
            if skipped:
                expected["note"] += (
                    f"; no column_denied probe for {', '.join(skipped)}: the "
                    "widened access carries no source expectation")
            add("row_count", key, ordered, expected)
    probes.sort(key=lambda p: (p["source_role"], p["kind"], p["table"],
                               p["columns"]))
    return probes


def run_probes(probes, backend, pg_ci):
    """Run every probe: the expected count on PostgreSQL (read-only, as the
    pipeline user, which is the owner or a superuser and so bypasses RLS)
    when pg_ci is given, the actual through backend.probe. A probe passes
    when the status matches and, when both counts are known, the counts
    match. unevaluable and error never pass. A PostgreSQL count that fails
    (for example a predicate that reads a session setting the pipeline
    user has not set) never aborts the run: that probe's expected status
    becomes "error" with the message in its note, it fails, and the
    remaining probes still run."""
    results = []
    for probe in probes:
        p = copy.deepcopy(probe)
        exp = p["expected"]
        if pg_ci is not None and exp.get("row_count_sql_pg"):
            try:
                rows = pg.query_rows(pg_ci, exp["row_count_sql_pg"],
                                     readonly=True)
                exp["row_count"] = int(rows[0][0])
            except (pg.PgError, OSError, ValueError, TypeError,
                    IndexError) as exc:
                exp["status"] = "error"
                exp["row_count"] = None
                exp["note"] = ((f"{exp.get('note')}; " if exp.get("note")
                                else "")
                               + f"the PostgreSQL count failed: {exc}")
        actual = backend.probe(p["principal"], p["probe_service_account"],
                               p["dataset"], p["table"], list(p["columns"]))
        p["actual"] = {"status": actual.get("status"),
                       "row_count": actual.get("row_count"),
                       "reason": actual.get("reason", "")}
        status = p["actual"]["status"]
        ok = status in ("ok", "denied") and status == exp["status"]
        if ok and exp.get("row_count") is not None \
                and p["actual"]["row_count"] is not None:
            ok = int(exp["row_count"]) == int(p["actual"]["row_count"])
        p["pass"] = ok
        results.append(p)
    return results


def probes_pass(results):
    """True only when at least one probe ran and every probe passed; an
    empty probe set proves nothing."""
    return bool(results) and all(r.get("pass") for r in results)


# ------------------------------------------------------------------- CLI

def _write_json(path, doc):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8",
                          newline="\n")


def _write_text(path, text):
    """LF on every platform: the rendered .sh files must run on Linux and
    macOS, and every artifact should match bq_schema's."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8", newline="\n")


def _load_json_artifact(path, what, required_key, hint):
    path = Path(path)
    if not path.exists():
        raise SecurityPlanError(f"{path} not found; {hint}")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SecurityPlanError(f"{path} is not JSON: {exc}")
    if not isinstance(doc, dict) or not isinstance(doc.get(required_key), list):
        raise SecurityPlanError(
            f"{path} is not a {what} (missing the {required_key} list)")
    return doc


def _load_context(args):
    mig = config.load_migration(args.root, args.migration)
    if mig.get("provider") != "bigquery":
        raise SecurityPlanError(
            f"migration {args.migration} has provider {mig.get('provider')!r}; "
            "bq-security applies to provider bigquery only")
    bq_cfg = config.bigquery_config(mig, args.migration)
    ws = config.workspace(args.root, args.migration)
    return mig, bq_cfg, ws


def _load_plan(art):
    plan = _load_json_artifact(
        art / PLAN_FILE, "security plan", "bindings",
        "run bq-security plan first")
    check_plan(plan)
    return plan


def _load_inputs(art):
    sec = _load_json_artifact(
        art / "security.json", "security inventory", "roles",
        "run security inventory --out artifacts/security.json first")
    inv = _load_json_artifact(
        art / "inventory.json", "source inventory", "tables",
        "run inventory --out artifacts/inventory.json first")
    return sec, inv


def _cmd_plan(args, bq_cfg, ws):
    art = ws / "artifacts"
    if args.template:
        sec = _load_json_artifact(
            art / "security.json", "security inventory", "roles",
            "run security inventory --out artifacts/security.json first")
        path = ws / bq_cfg["principal_map"]
        if path.exists() and not args.force:
            raise SecurityPlanError(
                f"{path} exists; refusing to overwrite the operator's "
                "principal map without --force")
        _write_text(path, principal_map_template(sec))
        print(f"wrote {path}")
        return 0
    sec, inv = _load_inputs(art)
    pmap = config.load_principal_map(str(ws / bq_cfg["principal_map"]))
    resolutions = {}
    res_path = art / RESOLUTIONS_FILE
    if res_path.exists():
        resolutions = json.loads(res_path.read_text(encoding="utf-8"))
        if not isinstance(resolutions, dict):
            raise SecurityPlanError(f"{res_path} must hold a JSON object")
        for section in ("views", "policies"):
            value = resolutions.get(section)
            if value is not None and not isinstance(value, dict):
                raise SecurityPlanError(
                    f"{res_path}: {section} must be a JSON object keyed "
                    "by the review item (schema.name for views, "
                    "schema.table/policy for policies), not "
                    f"{type(value).__name__}")
    plan = plan_security(sec, inv, bq_cfg, pmap, resolutions)
    _write_json(art / PLAN_FILE, plan)
    _write_text(art / PLAN_MD, render_plan_markdown(plan))
    for name, text in render_apply_scripts(plan, bq_cfg).items():
        _write_text(art / APPLY_DIR / name, text)
    review_path = Path(args.review_out) if args.review_out else art / REVIEW_FILE
    review = {}
    if review_path.exists():
        try:
            review = json.loads(review_path.read_text(encoding="utf-8"))
        except ValueError:
            review = {}
        if not isinstance(review, dict):
            review = {}
    review.setdefault("views", {})
    review["policies"] = review_items(plan)
    _write_json(review_path, review)
    counts = {s: 0 for s in SEVERITY_RANK}
    for f in plan["findings"]:
        counts[f["severity"]] += 1
    print(f"wrote {art / PLAN_FILE} ({len(plan['bindings'])} bindings, "
          f"{len(plan['policy_tags'])} policy tags, "
          f"{len(plan['row_policies'])} row policies, "
          f"{len(plan['authorized_views'])} authorized views)")
    print("findings: " + ", ".join(f"{counts[s]} {s}" for s in SEVERITY_RANK))
    for f in plan["findings"]:
        if f["severity"] == "WARNING":
            print(f"  WARNING {f['code']} {f['subject']}: {f['message']}")
    n_review = len(review["policies"])
    print(f"review: {n_review} row policy predicates need the sql-translator "
          f"({review_path})")
    return 0


def _cmd_apply(args, bq_cfg, ws):
    art = ws / "artifacts"
    plan = _load_plan(art)
    # Refuse before the backend (and its operation log) is touched.
    refuse_unresolved(plan)
    backend = bq_backend.make_backend(bq_cfg, args.migration, ws)
    result = apply_plan(plan, backend, log=backend.log)
    doc = dict(result, mode=backend.mode, migration=args.migration,
               project=plan.get("project"))
    _write_json(art / APPLIED_FILE, doc)
    print(f"applied {result['ops']} operations ({backend.mode}); wrote "
          f"{art / APPLIED_FILE}")
    return 0


def _cmd_verify(args, bq_cfg, ws):
    art = ws / "artifacts"
    plan = _load_plan(art)
    applied_path = art / APPLIED_FILE
    if applied_path.exists():
        try:
            applied = json.loads(applied_path.read_text(encoding="utf-8"))
        except ValueError:
            applied = {}
        if isinstance(applied, dict):
            plan["applied"] = {"taxonomy": applied.get("taxonomy"),
                               "tags": dict(applied.get("tags") or {})}
    backend = bq_backend.make_backend(bq_cfg, args.migration, ws)
    verdict = verify_plan(plan, backend)
    verdict = dict(verdict, mode=backend.mode, migration=args.migration)
    _write_json(art / VERIFY_FILE, verdict)
    failed = [c for c in verdict["checks"] if not c["pass"]]
    for c in failed:
        print(f"  FAIL {c['name']}: expected {c['expected']}, "
              f"actual {c['actual']}")
    label = f"({backend.mode}): {len(verdict['checks'])} checks, "
    if verdict["pass"]:
        print(f"SECURITY VERIFY PASSED {label}enforcement active; wrote "
              f"{art / VERIFY_FILE}")
        return 0
    print(f"SECURITY VERIFY FAILED {label}{len(failed)} failed, enforcement "
          f"active: {verdict['enforcement_active']}; wrote "
          f"{art / VERIFY_FILE}")
    return 1


def _cmd_probes(args, mig, bq_cfg, ws):
    art = ws / "artifacts"
    plan = _load_plan(art)
    sec, inv = _load_inputs(art)
    pmap = config.load_principal_map(str(ws / bq_cfg["principal_map"]))
    probes = probe_set(plan, sec, inv, pmap, bq_cfg)
    doc = {"mode": bq_cfg["mode"], "migration": args.migration,
           "ran": False, "pass": None, "skipped": not probes,
           "source_compared": None, "probes": probes}
    if not args.run:
        _write_json(art / PROBES_FILE, doc)
        print(f"wrote {art / PROBES_FILE} ({len(probes)} probes; add --run "
              "to execute them)")
        return 0
    if not probes:
        # nothing ran, so nothing was validated: the file says skipped and
        # the playbook treats that as not a pass in live mode
        doc["ran"] = True
        doc["pass"] = False
        _write_json(art / PROBES_FILE, doc)
        hint = ("add probe_service_account entries to the principal map"
                if bq_cfg["mode"] == "live"
                else "map at least one role in the principal map")
        print(f"SECURITY PROBES SKIPPED: no probes ({hint}); wrote "
              f"{art / PROBES_FILE}")
        return 0
    backend = bq_backend.make_backend(bq_cfg, args.migration, ws)
    pg_ci = None if args.no_source else config.source_conn(mig)
    results = run_probes(probes, backend, pg_ci)
    ok = probes_pass(results)
    doc["ran"] = True
    doc["mode"] = backend.mode
    doc["pass"] = ok
    doc["source_compared"] = pg_ci is not None
    doc["probes"] = results
    _write_json(art / PROBES_FILE, doc)
    passed = sum(1 for r in results if r["pass"])
    for r in results:
        if not r["pass"]:
            note = r["expected"].get("note") or ""
            print(f"  FAIL {r['kind']} {r['source_role']} on "
                  f"{r['dataset']}.{r['table']} {r['columns']}: expected "
                  f"{r['expected']['status']} "
                  f"{r['expected']['row_count']}, actual "
                  f"{r['actual']['status']} {r['actual']['row_count']} "
                  f"({r['actual']['reason']})"
                  + (f"; {note}" if r["expected"]["status"] == "error" else ""))
    verdict = "PASSED" if ok else "FAILED"
    label = backend.mode + ("" if pg_ci is not None
                            else ", status only, counts not compared")
    print(f"SECURITY PROBES {verdict} ({label}): {passed} of "
          f"{len(results)} probes; wrote {art / PROBES_FILE}")
    return 0 if ok else 1


def main(argv):
    parser = argparse.ArgumentParser(prog="dbcarry.py bq-security")
    parser.add_argument("--root", default=".",
                        help="project root holding migrations/")
    parser.add_argument("--migration", default=None)
    sub = parser.add_subparsers(dest="verb", required=True)
    p_plan = sub.add_parser("plan", help="write the security plan and the "
                                         "apply scripts")
    p_plan.add_argument("--template", action="store_true",
                        help="write security/principal-map.yaml with every "
                             "role and empty principals, nothing else")
    p_plan.add_argument("--force", action="store_true",
                        help="with --template: overwrite an existing map")
    p_plan.add_argument("--review-out", default=None,
                        help="where to write the review items (default "
                             "artifacts/translation-review.json)")
    p_apply = sub.add_parser("apply", help="apply the plan through the "
                                           "backend")
    p_verify = sub.add_parser("verify", help="read every control back; "
                                             "exit 1 on any miss")
    p_probes = sub.add_parser("probes", help="build (and with --run execute) "
                                             "the probe set")
    p_probes.add_argument("--run", action="store_true")
    p_probes.add_argument("--no-source", action="store_true",
                          help="do not compute expected counts on PostgreSQL")
    for p in (p_plan, p_apply, p_verify, p_probes):
        p.add_argument("--root", default=argparse.SUPPRESS,
                       help=argparse.SUPPRESS)
        p.add_argument("--migration", default=argparse.SUPPRESS,
                       help=argparse.SUPPRESS)
    args = parser.parse_args(argv[1:])
    if args.migration is None:
        parser.error("the following arguments are required: --migration")
    try:
        bq_backend.check_migration_name(args.migration)
        mig, bq_cfg, ws = _load_context(args)
        if args.verb == "plan":
            return _cmd_plan(args, bq_cfg, ws)
        if args.verb == "apply":
            return _cmd_apply(args, bq_cfg, ws)
        if args.verb == "verify":
            return _cmd_verify(args, bq_cfg, ws)
        return _cmd_probes(args, mig, bq_cfg, ws)
    except (config.ConfigError, bq_backend.BackendError, SecurityPlanError,
            pg.PgError) as exc:
        print(f"{ERROR_PREFIX}: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        print(f"{ERROR_PREFIX}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(["bq-security"] + sys.argv[1:]))
