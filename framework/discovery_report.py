"""Discovery documents: what a platform's credentials can see, as a readable page.

A `kind: discovery` fetcher enumerates a platform and writes one document in the
shape of framework/schemas/discovery_schema.json. The runner points it at
`<run>/discovery/` and envelopes it like evidence, so the run id, exit code and
failure reason travel with it. Neither uploader reads that directory: discovery
output describes a tenant, it is not a claim about one.

This module is the platform-agnostic half: find the documents in a run, unwrap
and validate them, and render them as Markdown. Every platform's fetcher emits
the same shape, which is the whole reason one renderer is enough.

See docs/discovery.md.
"""

from __future__ import annotations

import base64
import html
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from jsonschema import Draft202012Validator

from framework.envelope import is_enveloped

# Subdirectory of the run dir discovery fetchers write to. The runner points
# EVIDENCE_DIR here for a discovery fetcher, so fetchers never name it.
DISCOVERY_DIR = "discovery"

_HERE = Path(__file__).resolve().parent
_SCHEMA_PATH = _HERE / "schemas" / "discovery_schema.json"
_TEMPLATE_PATH = _HERE / "assets" / "discovery_report.html"
_FONT_PATH = _HERE / "assets" / "open-sauce-sans.woff2"
# fetchers/logos/<category>.<ext>: the same marks the TUI and README use.
_LOGOS_DIR = _HERE.parent / "fetchers" / "logos"
_LOGO_TYPES = {".svg": "image/svg+xml", ".png": "image/png", ".jpeg": "image/jpeg", ".jpg": "image/jpeg"}

FORMATS = ("html", "md")

# A page with tens of thousands of rows is one nobody can open. Past this many
# the HTML table stops and says so; the JSON keeps everything.
HTML_MAX_ROWS = 2000

# Below this many rows a filter box is clutter.
FILTER_MIN_ROWS = 8

# How a platform is written in prose. Anything missing is title-cased from the
# category name, which is right for most of them.
_DISPLAY_NAMES = {
    "aws": "AWS", "gcp": "Google Cloud", "k8s": "Kubernetes", "knowbe4": "KnowBe4",
    "github": "GitHub", "gitlab": "GitLab", "servicenow": "ServiceNow",
    "sentinelone": "SentinelOne", "crowdstrike": "CrowdStrike", "betterstack": "Better Stack",
}

# A resource type with thousands of items (enrollments, say, if a fetcher lists
# them) makes a page nobody reads. The full list stays in the JSON.
MAX_ROWS = 200

_STATUS_LABEL = {
    "ok": "ok",
    "not_enabled": "not enabled",
    "denied": "denied",
    "error": "error",
    "partial": "partly read",
    "partly_enabled": "partly enabled",
    "truncated": "truncated",
}


def _validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(_SCHEMA_PATH.read_text()))


def validate(doc: Any) -> List[str]:
    """Schema violations in a discovery document, as readable strings. Empty = valid.

    Adds the one rule JSON Schema cannot say: each (type, scope) pair appears
    once, or the page would add the same listing up twice."""
    errors = sorted(_validator().iter_errors(doc), key=lambda e: list(e.path))
    out = [f"{'/'.join(str(p) for p in e.path) or '(root)'}: {e.message}" for e in errors]
    seen = set()
    resources = doc.get("resources") if isinstance(doc, dict) else None
    for i, res in enumerate(resources if isinstance(resources, list) else []):
        if not isinstance(res, dict):
            continue
        key = (res.get("type"), json.dumps(res.get("scope") or {}, sort_keys=True))
        if key in seen:
            out.append(f"resources/{i}: duplicate entry for type {res.get('type')!r} in scope {key[1]}")
        seen.add(key)
    return out


def load(path: Path) -> Tuple[Optional[dict], dict]:
    """(envelope metadata or None, discovery document) from one file.

    Accepts the enveloped file the runner leaves behind and the bare document a
    fetcher writes when run by hand, so `render` works on either.
    """
    try:
        raw = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"{path}: cannot read as JSON ({e})") from e
    if is_enveloped(raw):
        return raw.get("metadata") or {}, raw.get("payload")
    return None, raw


def find_documents(path: Path) -> List[Path]:
    """The discovery documents at `path`: a file, a run dir, or its discovery/ dir."""
    p = Path(path)
    if p.is_file():
        return [p]
    if (p / DISCOVERY_DIR).is_dir():
        p = p / DISCOVERY_DIR
    if not p.is_dir():
        raise ValueError(f"{path}: no such file or directory")
    return sorted(
        f for f in p.glob("*.json") if not f.name.startswith("_")
    )


# --------------------------------------------------------------------------- #
# Grouping: one view per resource type, however many scopes it was listed in
# --------------------------------------------------------------------------- #

# Unread: nothing was listed, so the count is null. Gaps: unread because we
# could not tell. not_enabled is unread but NOT a gap — the platform answered
# that the feature is off, so there is nothing of that type to list.
_UNREAD = {"denied", "error", "not_enabled"}
_GAPS = {"denied", "error"}


def _merge_summaries(summaries: List[dict]) -> dict:
    merged: Dict[str, Any] = {}
    for summary in summaries:
        for key, value in summary.items():
            if isinstance(value, dict):
                bucket = merged.setdefault(key, {})
                for k, v in value.items():
                    if isinstance(v, (int, float)):
                        bucket[k] = bucket.get(k, 0) + v
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                merged[key] = merged.get(key, 0) + value
            else:
                merged.setdefault(key, value)
    return merged


def group_resources(resources: List[dict]) -> List[dict]:
    """Fold the entries of each type into one view, in first-seen order.

    An unscoped type passes through unchanged (plus `scopes: []`). A scoped type
    becomes one view whose count adds up the scopes that were read, whose items
    carry their scope as leading columns, and whose `status` is the shared
    status when every scope agrees, or `partial` when they do not. The count is
    a lower bound (`truncated`) whenever any scope was denied, errored or cut
    short, so a total never looks complete when part of it is missing. A scope
    where the feature is not enabled is a complete answer (there is nothing
    there), so it does not make the count a lower bound.
    """
    order: List[str] = []
    by_type: Dict[str, List[dict]] = {}
    for res in resources:
        t = res.get("type", "")
        if t not in by_type:
            order.append(t)
            by_type[t] = []
        by_type[t].append(res)

    groups = []
    for t in order:
        entries = by_type[t]
        if len(entries) == 1 and not entries[0].get("scope"):
            groups.append({**entries[0], "scopes": []})
            continue
        statuses = {e.get("status") for e in entries}
        read = [e for e in entries if e.get("count") is not None]
        unread = [e for e in entries if e.get("status") != "ok"]
        gaps = [e for e in entries if e.get("status") in _GAPS]
        items: Optional[List[dict]] = None
        if any(e.get("items") is not None for e in entries):
            items = [
                {**(e.get("scope") or {}), **item}
                for e in entries for item in (e.get("items") or [])
            ]
        reasons = [e["reason"] for e in unread if e.get("reason")]
        group = {
            "type": t,
            "label": entries[0].get("label"),
            "note": entries[0].get("note"),
            "status": statuses.pop() if len(statuses) == 1 else "partial",
            "count": sum(e["count"] for e in read) if read else None,
            "truncated": bool(read) and (any(e.get("truncated") for e in entries) or bool(gaps)),
            "items": items,
            "source": entries[0].get("source"),
            "scopes": entries,
        }
        if reasons:
            group["reason"] = max(set(reasons), key=reasons.count)
        summaries = [e["summary"] for e in entries if e.get("summary")]
        if summaries:
            group["summary"] = _merge_summaries(summaries)
        groups.append(group)
    return groups


def _scope_label(entries: List[dict]) -> str:
    """What the scopes are called, from their keys: "region", "subscription"."""
    keys = {k for e in entries for k in (e.get("scope") or {})}
    return "/".join(sorted(keys)) if keys else "scope"


def _problem_text(group: dict) -> str:
    """One line on what went wrong with a type, for the verdict."""
    scopes = group.get("scopes") or []
    if not scopes:
        state = _state(group) or "ok"
        return f"{_STATUS_LABEL.get(state, state)}" + (f" — {group['reason']}" if group.get("reason") else "")
    noun = _scope_label(scopes)
    tally: Dict[str, int] = {}
    for e in scopes:
        key = "truncated" if e.get("status") == "ok" and e.get("truncated") else e.get("status", "")
        tally[key] = tally.get(key, 0) + 1
    parts = [f"{_STATUS_LABEL.get(k, k)} in {n}" for k, n in sorted(tally.items(), key=lambda kv: -kv[1])]
    text = f"{', '.join(parts)} of {len(scopes)} {noun}s"
    if group.get("reason"):
        text += f" — {group['reason']}"
    return text


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        value = json.dumps(value, ensure_ascii=False)
    # A pipe ends the cell and a newline ends the row; tenant data has both.
    return str(value).replace("|", "\\|").replace("\n", " ")


def _columns(items: List[dict]) -> List[str]:
    cols = ["id", "name"]
    for item in items:
        for key in item:
            if key not in cols:
                cols.append(key)
    return cols


def _count_text(res: dict) -> str:
    count = res.get("count")
    if count is None:
        return "—"
    return f"≥ {count}" if res.get("truncated") else str(count)


def _summary_lines(summary: dict) -> List[str]:
    lines = []
    for key, value in summary.items():
        if isinstance(value, dict):
            parts = ", ".join(f"{k}: {v}" for k, v in value.items())
            lines.append(f"- **{key}**: {parts or '—'}")
        else:
            lines.append(f"- **{key}**: {value}")
    return lines


def render_markdown(doc: dict, metadata: Optional[dict] = None) -> str:
    """One discovery document as a Markdown page: a summary table, then a section
    per resource type that lists its items."""
    platform = doc.get("platform") or "unknown platform"
    out: List[str] = [f"# Discovery: {platform}", ""]

    facts = []
    if doc.get("identity"):
        facts.append(f"**Identity:** {doc['identity']}")
    for key, value in (doc.get("scope") or {}).items():
        facts.append(f"**{key}:** {value}")
    facts.append(f"**Collected:** {doc.get('collected_at')}")
    if metadata:
        facts.append(f"**Run:** {metadata.get('run_id')}")
        facts.append(f"**Fetcher:** {metadata.get('fetcher_name')} {metadata.get('fetcher_version')}")
    out += ["  \n".join(facts), ""]

    if metadata and metadata.get("exit_code") not in (0, None):
        out += [
            f"> **The discovery run failed (exit {metadata['exit_code']}).** "
            f"{metadata.get('error') or ''}".rstrip(),
            "> Counts below may be incomplete.",
            "",
        ]

    resources = group_resources(doc.get("resources") or [])
    not_ok = [r for r in resources if _is_gap(r)]
    if not_ok:
        out += [
            f"> {len(not_ok)} of {len(resources)} resource types could not be fully read. "
            "A type that was denied or failed is **unknown**, not empty.",
            ">",
        ]
        out += [f"> - **{r.get('type')}**: {_problem_text(r)}" for r in not_ok]
        out.append("")
    off = [r for r in resources if _state(r) in ("not_enabled", "partly_enabled")]
    if off:
        out += ["Not enabled: " + "; ".join(
            f"**{r.get('type')}**" + (f" ({_problem_text(r)})" if r.get("scopes") else "") for r in off
        ) + ".", ""]

    out += ["## Summary", "", "| Resource | Status | Count | Source |", "|---|---|---|---|"]
    for res in resources:
        raw = str(res.get("status", ""))
        status = _STATUS_LABEL.get(raw, raw)
        if res.get("truncated") and raw != "partial":
            status += " (truncated)"
        out.append(
            f"| {_cell(res.get('type'))} | {status} | {_count_text(res)} | `{_cell(res.get('source'))}` |"
        )
    out.append("")

    for res in resources:
        out += [f"## {res.get('type')} ({_count_text(res)})", ""]
        out += [f"Source: `{res.get('source')}`", ""]
        if _state(res):
            detail = _problem_text(res) if res.get("scopes") else res.get("reason", "")
            out += [f"**{_STATUS_LABEL.get(_state(res) or '', _state(res))}:** {detail}", ""]
        scopes = res.get("scopes") or []
        if len(scopes) > 1:
            keys = list(dict.fromkeys(k for e in scopes for k in (e.get("scope") or {})))
            out.append("| " + " | ".join(keys + ["status", "count", "reason"]) + " |")
            out.append("|" + "---|" * (len(keys) + 3))
            for e in scopes:
                sc = e.get("scope") or {}
                out.append("| " + " | ".join(
                    [_cell(sc.get(k)) for k in keys]
                    + [_STATUS_LABEL.get(e.get("status"), e.get("status")), _count_text(e), _cell(e.get("reason"))]
                ) + " |")
            out.append("")
        if res.get("summary"):
            out += _summary_lines(res["summary"]) + [""]
        items = res.get("items")
        if items is None:
            if res.get("status") == "ok":
                out += ["_Count only: items are not listed for this type._", ""]
            continue
        if not items:
            out += ["_None._", ""]
            continue
        cols = _columns(items)
        out.append("| " + " | ".join(cols) + " |")
        out.append("|" + "---|" * len(cols))
        for item in items[:MAX_ROWS]:
            out.append("| " + " | ".join(_cell(item.get(c)) for c in cols) + " |")
        if len(items) > MAX_ROWS:
            out.append("")
            out.append(f"_{len(items) - MAX_ROWS} more in the JSON._")
        out.append("")

    return "\n".join(out).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# HTML: the review page
# --------------------------------------------------------------------------- #

_ISO_DATETIME = re.compile(r"^(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}")
_TONES = 4


def display_name(platform: str) -> str:
    return _DISPLAY_NAMES.get(platform, platform.replace("_", " ").title())


# Words a type or field name is likely to contain that read wrong in sentence
# case. Generic tech vocabulary, not one platform's: a fetcher that needs more
# sets `label` on the resource.
_ACRONYMS = {
    "acl", "api", "arn", "aws", "az", "cidr", "cpu", "dns", "ebs", "ec2", "ecr", "ecs", "efs",
    "eks", "gcp", "iam", "id", "ip", "kms", "mfa", "rds", "s3", "sns", "sql", "sqs", "sso",
    "ssl", "tls", "url", "vm", "vpc", "waf",
}


def _label(key: str) -> str:
    """Type or field name -> sentence case, acronyms kept ("ec2_instance" -> "EC2 instance")."""
    words = key.replace("_", " ").split()
    words = [w.upper() if w.lower() in _ACRONYMS else w for w in words]
    text = " ".join(words)
    return text[:1].upper() + text[1:]


def _type_label(res: dict) -> str:
    return res.get("label") or _label(res.get("type", ""))


def _plural(label: str, count: Optional[int]) -> str:
    """Pluralize the last word of a label unless the count is exactly 1. A
    trailing parenthetical stays put: "Web ACL (CloudFront)" -> "Web ACLs (CloudFront)"."""
    if count == 1:
        return label
    head, paren = label, ""
    m = re.match(r"^(.*?)(\s*\([^)]*\))$", label)
    if m:
        head, paren = m.group(1), m.group(2)
    if re.search(r"[^aeiou]y$", head):
        head = head[:-1] + "ies"
    elif head.endswith(("s", "x", "ch", "sh")):
        head += "es"
    else:
        head += "s"
    return head + paren


def _when(value: Any) -> str:
    """An ISO timestamp as "2026-10-07 23:34 UTC"; anything else unchanged."""
    m = re.match(r"^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2})(?::\d{2}(?:\.\d+)?)?Z$", str(value or ""))
    return f"{m.group(1)} {m.group(2)}:{m.group(3)} UTC" if m else str(value)


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _logo_uri(platform: str) -> Optional[str]:
    for ext, mime in _LOGO_TYPES.items():
        path = _LOGOS_DIR / f"{platform}{ext}"
        if path.is_file():
            return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode()}"
    return None


def _cell_html(key: str, value: Any) -> Tuple[str, str, str]:
    """(class, sort key, inner html) for one table cell."""
    if value is None or value == [] or value == "":
        return "", "", '<span class="nil">—</span>'
    if isinstance(value, bool):
        return "", "1" if value else "0", "Yes" if value else "No"
    if isinstance(value, (int, float)):
        return "n", str(value), _e(f"{value:,}" if isinstance(value, int) else value)
    if isinstance(value, list):
        text = ", ".join(str(v) for v in value)
        return "", text, _e(text)
    if isinstance(value, dict):
        text = json.dumps(value, ensure_ascii=False)
        return "", text, f'<code>{_e(text)}</code>'
    text = str(value)
    m = _ISO_DATETIME.match(text)
    if m:
        return "", text, f'<time datetime="{_e(text)}" title="{_e(text)}">{_e(m.group(1))}</time>'
    return "", text, _e(text)


def _summary_html(summary: dict) -> str:
    blocks = []
    for key, value in summary.items():
        name = _label(key.removeprefix("by_"))
        if not isinstance(value, dict):
            blocks.append(f'<div><div class="dim-name">{_e(name)}</div><p class="note">{_e(value)}</p></div>')
            continue
        parts = sorted(
            ((k, v) for k, v in value.items() if isinstance(v, (int, float))),
            key=lambda kv: -kv[1],
        )
        total = sum(v for _, v in parts) or 1
        bar = "".join(
            f'<span class="t{min(i, _TONES - 1) + 1}" style="width:{v * 100 / total:.2f}%" '
            f'title="{_e(k)}: {v}"></span>'
            for i, (k, v) in enumerate(parts)
        )
        legend = "".join(
            f'<li><i class="t{min(i, _TONES - 1) + 1}"></i>{_e(k)} <b>{v:,}</b></li>'
            for i, (k, v) in enumerate(parts)
        )
        blocks.append(
            f'<div><div class="dim-name">{_e(name)}</div>'
            f'<div class="bar" role="img" aria-label="{_e(name)} breakdown">{bar}</div>'
            f'<ul class="legend">{legend}</ul></div>'
        )
    return f'<div class="summary">{"".join(blocks)}</div>'


def _is_numeric_column(items: List[dict], col: str) -> bool:
    values = [i.get(col) for i in items if i.get(col) is not None]
    return bool(values) and all(
        isinstance(v, (int, float)) and not isinstance(v, bool) for v in values
    )


def _header(col: str) -> str:
    return {"id": "ID", "name": "Name"}.get(col, _label(col))


def _table_html(res: dict, table_id: str) -> str:
    items = res.get("items") or []
    cols = _columns(items)
    # Many platforms name things by their id (an IAM role, a DynamoDB table);
    # the second identical column is noise.
    if items and all(str(i.get("id")) == str(i.get("name")) for i in items):
        cols.remove("id")
    numeric = {c for c in cols if _is_numeric_column(items, c)}
    noun = _plural(_type_label(res), len(items))
    noun = noun if noun[:2].isupper() else noun.lower()

    head = "".join(
        f'<th scope="col" class="n">{_e(_header(c))}</th>' if c in numeric
        else f'<th scope="col">{_e(_header(c))}</th>'
        for c in cols
    )
    rows = []
    for item in items[:HTML_MAX_ROWS]:
        cells = []
        for c in cols:
            cls, sort_key, inner = _cell_html(c, item.get(c))
            # id and name are styled by role, whatever their values look like.
            cls = {"id": "id", "name": "name"}.get(c, cls)
            attr = f' class="{cls}"' if cls else ""
            cells.append(f'<td{attr} data-v="{_e(sort_key)}">{inner}</td>')
        rows.append(f"<tr>{''.join(cells)}</tr>")

    tools = "" if len(items) < FILTER_MIN_ROWS else (
        f'<div class="tools"><input type="search" data-filter="{table_id}" '
        f'placeholder="Filter {len(items):,} {_e(noun)}…" aria-label="Filter {_e(noun)}">'
        f'<span class="shown">{len(items):,} shown</span></div>'
    )
    more = (
        f'<p class="more">Showing the first {HTML_MAX_ROWS:,} of {len(items):,}; '
        "the rest are in the JSON document.</p>"
        if len(items) > HTML_MAX_ROWS else ""
    )
    return (
        f'{tools}<div class="table-wrap"><table id="{table_id}" data-sortable>'
        f"<thead><tr>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>{more}"
    )


_NIL = '<span class="nil">—</span>'


def _scopes_html(entries: List[dict]) -> str:
    """Per-scope status for a type listed in several places. Unread scopes
    first, so a reviewer sees the gaps without scrolling 17 regions."""
    keys = list(dict.fromkeys(k for e in entries for k in (e.get("scope") or {})))
    ordered = sorted(entries, key=lambda e: (e.get("status") == "ok" and not e.get("truncated"),))
    rows = []
    for e in ordered:
        sc = e.get("scope") or {}
        status = e.get("status", "")
        word = "truncated" if status == "ok" and e.get("truncated") else status
        cells = "".join(f'<td class="id">{_e(sc.get(k, ""))}</td>' for k in keys)
        cls = f"state {word}" if word != "ok" else ""
        cells += f'<td><span class="{cls}">{_e(_STATUS_LABEL.get(word, word))}</span></td>'
        cells += f'<td class="n">{_count_html(e)}</td>'
        reason = _e(e.get("reason", "")) or _NIL
        cells += f"<td>{reason}</td>"
        rows.append(f"<tr>{cells}</tr>")
    head = "".join(f'<th scope="col">{_e(_label(k))}</th>' for k in keys)
    head += '<th scope="col">Status</th><th scope="col" class="n">Count</th><th scope="col">Reason</th>'
    gaps = sum(1 for e in entries if e.get("status") in _GAPS or e.get("truncated"))
    off = sum(1 for e in entries if e.get("status") == "not_enabled")
    unread = gaps + off
    caption = f"Listed in {len(entries)} {_e(_plural(_scope_label(entries), len(entries)))}"
    parts = ([f"{gaps} not fully read"] if gaps else []) + ([f"{off} not enabled"] if off else [])
    caption += ", " + ", ".join(parts) if parts else ", all read"
    return (
        f'<details class="scopes"{" open" if unread else ""}><summary>{caption}</summary>'
        f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead>'
        f"<tbody>{''.join(rows)}</tbody></table></div></details>"
    )


def _count_html(res: dict) -> str:
    count = res.get("count")
    if count is None:
        return "—"
    return f"≥ {count:,}" if res.get("truncated") else f"{count:,}"


def _state(res: dict) -> Optional[str]:
    """The word a tile shows under its count, or None when there is nothing to say.

    denied / error / partial / truncated are gaps (see `_is_gap`).
    not_enabled and partly_enabled are answers: the feature is off, everywhere
    or in some scopes."""
    status = res.get("status")
    if status in _UNREAD:
        return status
    if status == "partial":
        scopes = res.get("scopes") or []
        if any(e.get("status") in _GAPS for e in scopes):
            return "partial"
        if res.get("truncated"):
            return "truncated"
        return "partly_enabled"
    if res.get("truncated"):
        return "truncated"
    return None


def _is_gap(res: dict) -> bool:
    """True when some of this type could not be read, so its count is not the whole story."""
    return _state(res) in ("denied", "error", "partial", "truncated")


def render_html(doc: dict, metadata: Optional[dict] = None) -> str:
    """One discovery document as a self-contained HTML page.

    The layout is driven by the document schema alone — masthead, verdict,
    a tile per resource type, then a section per type with its summary bars and
    a filterable, sortable table — so every discovery fetcher gets the same page
    with no per-platform code.
    """
    platform = doc.get("platform") or "unknown"
    name = display_name(platform)
    resources = group_resources(doc.get("resources") or [])
    out: List[str] = []

    logo = _logo_uri(platform)
    out.append('<header><p class="eyebrow">Discovery report</p><div class="title-row">')
    if logo:
        out.append(f'<img src="{logo}" alt="">')
    out.append(f"<h1>{_e(name)}</h1></div>")

    facts: List[Tuple[str, Any]] = []
    if doc.get("identity"):
        facts.append(("Identity", doc["identity"]))
    for key, value in (doc.get("scope") or {}).items():
        facts.append((_label(key), value))
    facts.append(("Collected", _when(doc.get("collected_at"))))
    if metadata and metadata.get("run_id"):
        facts.append(("Run", metadata["run_id"]))
    if metadata and metadata.get("fetcher_name"):
        facts.append(("Fetcher", f"{metadata['fetcher_name']} {metadata.get('fetcher_version') or ''}".strip()))
    def _fact(k: str, v: Any) -> str:
        # A long value (an ARN) gets two columns instead of wrapping in one.
        cls = ' class="wide"' if len(str(v)) > 28 else ""
        return f"<div{cls}><dt>{_e(k)}</dt><dd>{_e(v)}</dd></div>"

    out.append('<dl class="facts">' + "".join(_fact(k, v) for k, v in facts) + "</dl></header>")

    # Verdict: the one sentence a reviewer needs before trusting any number below.
    # Gaps (could not tell) are red and come first; features that are switched
    # off are an answer, so they are a plain note.
    problems = [r for r in resources if _is_gap(r)]
    off = [r for r in resources if _state(r) in ("not_enabled", "partly_enabled")]
    meta = metadata or {}
    failed_run = meta.get("exit_code") not in (0, None)

    def _link(r: dict) -> str:
        return f"<a href=\"#r-{_e(r.get('type'))}\">{_e(_plural(_type_label(r), 2))}</a>"

    def _off_text(r: dict) -> str:
        link = f"<a href=\"#r-{_e(r.get('type'))}\">{_e(_type_label(r))}</a>"
        scopes = r.get("scopes") or []
        if not scopes:
            return link
        noun = _plural(_scope_label(scopes), len(scopes))
        n_off = sum(1 for e in scopes if e.get("status") == "not_enabled")
        where = f"all {len(scopes)} {noun}" if n_off == len(scopes) else f"{n_off} of {len(scopes)} {noun}"
        return f"{link} ({_e(where)})"

    off_note = ""
    if off:
        off_note = '<p class="off-note">Not enabled: ' + "; ".join(_off_text(r) for r in off) + ".</p>"
    if problems or failed_run:
        lines = "".join(f"<li>{_link(r)}: {_e(_problem_text(r))}</li>" for r in problems)
        head = (
            f"<strong>{len(problems)} of {len(resources)} resource types could not be fully read.</strong> "
            "A type that was denied or failed is unknown, not empty."
            if problems else "<strong>The discovery run failed.</strong>"
        )
        if failed_run:
            head += f" The run exited {_e(meta['exit_code'])}: {_e(meta.get('error') or 'no reason given')}."
        out.append(f'<div class="verdict bad"><p>{head}</p>{"<ul>" + lines + "</ul>" if lines else ""}{off_note}</div>')
    else:
        out.append(
            f'<div class="verdict"><p><strong>All {len(resources)} resource types were read in full.</strong> '
            f"Every count below is complete.</p>{off_note}</div>"
        )

    out.append('<h2 class="section-label">At a glance</h2><nav class="glance">')
    for res in resources:
        state = _state(res)
        cls = "tile"
        if res.get("count") is None:
            cls += " unread"
        elif res.get("count") == 0 and not state:
            cls += " zero"
        state_html = f'<span class="state {_e(state)}">{_e(_STATUS_LABEL.get(state, state))}</span>' if state else ""
        out.append(
            f'<a class="{cls}" href="#r-{_e(res.get("type"))}"><span class="num">{_count_html(res)}</span>'
            f'<span class="label">{_e(_plural(_type_label(res), res.get("count")))}</span>{state_html}</a>'
        )
    out.append("</nav>")

    for i, res in enumerate(resources):
        rtype = res.get("type", "")
        out.append(f'<section class="resource" id="r-{_e(rtype)}"><div class="res-head">'
                   f"<h3>{_e(_plural(_type_label(res), res.get('count')))}</h3><span class=\"count\">{_count_html(res)}</span>"
                   f"<code>{_e(res.get('source', ''))}</code></div>")
        state = _state(res)
        # A fetcher's note says how to read this type's count, and replaces the
        # generic second line where the generic one would not be true.
        note = res.get("note")
        if state == "not_enabled":
            out.append(
                f'<div class="callout off"><p><strong>Not enabled.</strong> {_e(res.get("reason", ""))}</p>'
                f"<p>{_e(note) if note else 'The platform reports this feature as switched off, so there is nothing of this type.'}</p></div>"
            )
        elif state == "partly_enabled":
            out.append(f'<div class="callout off"><p><strong>Partly enabled.</strong> {_e(_problem_text(res))}</p>'
                       f"<p>{_e(note) if note else 'The count is complete: where the feature is off, there is nothing of this type.'}</p></div>")
        elif note:
            out.append(f'<p class="note">{_e(note)}</p>')
        elif state in _GAPS:
            out.append(
                f'<div class="callout"><p><strong>{_e(_label(state))}.</strong> {_e(res.get("reason", ""))}</p>'
                + ("<p>Listing stopped partway; the count is a lower bound.</p>" if res.get("truncated")
                   else "<p>This type is unknown, not empty.</p>")
                + "</div>"
            )
        elif state == "partial":
            noun = _scope_label(res.get("scopes") or [])
            out.append(f'<div class="callout warn"><p><strong>Partly read.</strong> {_e(_problem_text(res))}</p>'
                       f"<p>The count adds up only the {_e(noun)}s that could be read, so it is a lower bound.</p></div>")
        elif state == "truncated":
            out.append(f'<div class="callout warn"><p><strong>Truncated.</strong> {_e(res.get("reason", ""))}</p>'
                       "<p>The count is a lower bound.</p></div>")
        if len(res.get("scopes") or []) > 1:
            out.append(_scopes_html(res["scopes"]))
        if res.get("summary"):
            out.append(_summary_html(res["summary"]))
        items = res.get("items")
        if items is None:
            if res.get("status") in ("ok", "partial"):
                out.append('<p class="note">Counted, not listed: records of this type are about people '
                           "or too numerous to list.</p>")
        elif not items:
            out.append('<p class="note">None.</p>')
        else:
            out.append(_table_html(res, f"t{i}"))
        out.append("</section>")

    out.append(
        f'<p class="colophon">Generated by <code>paramify discovery render</code> from a discovery document '
        f'(schema {_e(doc.get("schema_version"))}). Read-only: nothing on this page was uploaded.</p>'
    )

    font = base64.b64encode(_FONT_PATH.read_bytes()).decode() if _FONT_PATH.is_file() else ""
    return (
        _TEMPLATE_PATH.read_text()
        .replace("<!--TITLE-->", _e(f"{name} discovery"))
        .replace("/*FONT*/", font)
        .replace("<!--BODY-->", "\n".join(out))
    )


_RENDERERS = {"html": render_html, "md": render_markdown}


def render_path(path: Path, formats: Sequence[str] = ("html",)) -> List[Dict[str, Any]]:
    """Render every discovery document at `path` to a page beside it, one file
    per format (`html`, `md`).

    Returns one record per document: its path, the files written, and any
    schema errors. An invalid document is still rendered — the page is how
    someone finds out what is wrong with it — but the errors are reported.
    """
    unknown = [f for f in formats if f not in _RENDERERS]
    if unknown:
        raise ValueError(f"unknown format(s): {', '.join(unknown)} (choose from {', '.join(FORMATS)})")
    results = []
    for doc_path in find_documents(path):
        metadata, doc = load(doc_path)
        errors = validate(doc)
        written = []
        if isinstance(doc, dict):
            for fmt in formats:
                out = doc_path.with_suffix(f".{fmt}")
                out.write_text(_RENDERERS[fmt](doc, metadata))
                written.append(str(out))
        results.append({"document": str(doc_path), "outputs": written, "errors": errors})
    return results
