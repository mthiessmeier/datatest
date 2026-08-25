#!/usr/bin/env python3
"""Calibration layer for the Baltic OSINT Watch.

This module preserves the collectors/reporting engine in monitor.py while
hardening event-vs-hypothesis discrimination, reducing API noise, and improving
publisher trust classification.
"""

from __future__ import annotations

from typing import Any

import monitor as core


def _get_rule(rule_id: str) -> dict[str, Any]:
    for candidate in core.INDICATORS:
        if candidate.get("id") == rule_id:
            return candidate
    raise KeyError(f"Indicator not found: {rule_id}")


# A policy warning about a possible attack must never be scored as the attack
# itself. The first deployment run exposed this exact lexical collision.
_modal_or_warning = [
    r"\b(?:could|may|might|possible|potential|would|scenario|proposal)\b",
    r"\b(?:plan(?:s|ned|ning)?|consider(?:s|ed|ing)?|warn(?:s|ed|ing)?)\b",
    r"\b(?:threat of|risk of|in (?:the )?event of|if russia attacks?)\b",
]

rule = _get_rule("H1-I08")
rule["exclude"] = _modal_or_warning + [r"\b(?:exercise|drill|simulation|tabletop)\b"]

rule = _get_rule("H1-I03")
rule["all_groups"] = [
    [
        r"combat air patrol", r"air defen[cs]e", r"awacs", r"aew&c",
        r"scrambl(?:e|ed|ing)", r"force protection", r"aircraft dispersal",
        r"missile defen[cs]e",
    ],
    [
        r"reinforc(?:e|ed|ement)", r"surge(?:d|s|ing)?", r"continuous patrol",
        r"heightened", r"elevated readiness", r"deploy(?:ed|ment|ing)",
        r"activat(?:e|ed|ion)", r"raised readiness", r"dispers(?:e|ed|al)",
    ],
]
rule["exclude"] = [
    r"\b(?:to|for|support(?:ing)?|deliver(?:y|ies|ed) to) ukraine\b",
    r"\bukraine (?:receives?|received|needs?|seeks?|requests?)\b",
    r"\b(?:planned|scheduled|routine) (?:exercise|rotation|training)\b",
]

rule = _get_rule("H1-I05")
rule["exclude"] = list(rule.get("exclude", [])) + [
    r"\b(?:could|may|might|would) deploy\b",
    r"\b(?:possible|potential|planned) deployment\b",
]

rule = _get_rule("H1-I07")
rule["exclude"] = _modal_or_warning + [r"\b(?:exercise|simulation|scenario)\b"]

# Require an attributable Russian messenger as well as the hostile narrative.
# Reporting that Lithuania fears a Russian false flag is context, not evidence
# that Moscow has started the attribution campaign.
rule = _get_rule("H1-I09")
rule.pop("any", None)
rule["all_groups"] = [
    [
        r"kremlin", r"russian (?:foreign|defen[cs]e) ministry",
        r"moscow (?:said|says|claims|claimed|accuses|accused|warns|warned)",
        r"russia (?:said|says|claims|claimed|accuses|accused|warns|warned|threatens|threatened)",
        r"\b(?:lavrov|peskov|zakharova)\b", r"russian state media",
        r"pro[- ]kremlin", r"russian military blogger",
    ],
    [
        r"legitimate target", r"retaliat(?:e|ed|ion)",
        r"baltic.{0,100}ukrain(?:e|ian).{0,100}(?:drone|attack|airspace)",
        r"ukrain(?:e|ian).{0,100}(?:from|through|using).{0,100}(?:baltic|latvia|lithuania|estonia)",
        r"allow(?:ed|ing).{0,80}ukrainian drones",
        r"launch(?:ed|ing).{0,80}from.{0,80}(?:baltic|latvia|lithuania|estonia)",
    ],
]
rule["exclude"] = [
    r"\b(?:lithuania|latvia|estonia|baltic states?) (?:warns?|said|says|fears?)\b",
    r"\b(?:possible|potential) false[- ]flag\b",
]

rule = _get_rule("H1-I10")
rule["exclude"] = _modal_or_warning + [r"\b(?:exercise|simulation|scenario)\b"]

# Preserve the Lithuanian warning as low-weight strategic context without
# misclassifying it as an executed operation.
core.INDICATORS.append(
    {
        "id": "C-I01",
        "name": "Baltic official warning of a possible false-flag UAS attack",
        "severity": "context",
        "weights": {"H1": 1.2},
        "all_groups": [
            [
                r"lithuanian (?:military )?intelligence",
                r"lithuania(?:n)? (?:defen[cs]e minister|officials?)",
                r"lithuania warns?",
            ],
            [
                r"false[- ]flag", r"captured ukrainian drone",
                r"reconstructed ukrainian drone", r"fake ukrainian drone",
            ],
            [r"critical infrastructure", r"baltic"],
        ],
    }
)


# Google News occasionally omits publisher domains from RSS metadata. Recover a
# conservative tier from the publisher name; unknown publishers remain tier 3.
_original_google_news = core.collect_google_news
_HIGH_RELIABILITY_NAMES = (
    "reuters", "associated press", "ap news", "bbc", "financial times",
    "wall street journal", "wsj", "bloomberg", "cbs news", "axios",
    "latvian public broadcasting", "lsm", "estonian public broadcasting",
    "err news", "lrt", "stars and stripes", "the war zone",
)
_OFFICIAL_NAMES = (
    "nato", "u.s. department of state", "us department of state",
    "u.s. department of defense", "u.s. department of war",
    "latvian ministry", "lithuanian ministry", "estonian ministry",
    "latvian armed forces", "lithuanian armed forces", "estonian defence forces",
)


def _collect_google_news(session: Any, query: dict[str, str], config: dict[str, Any], errors: list[str]) -> list[Any]:
    items = _original_google_news(session, query, config, errors)
    for item in items:
        publisher = item.source.lower()
        if any(name in publisher for name in _OFFICIAL_NAMES):
            item.tier = min(item.tier, 1)
        elif any(name in publisher for name in _HIGH_RELIABILITY_NAMES):
            item.tier = min(item.tier, 2)
    return items


core.collect_google_news = _collect_google_news


# GDELT's anonymous DOC endpoint is aggressively rate-limited. Use one broad
# request per sweep instead of repeating the request for every query family.
_original_gdelt = core.collect_gdelt
_gdelt_collected = False


def _collect_gdelt(session: Any, query: dict[str, str], config: dict[str, Any], errors: list[str]) -> list[Any]:
    global _gdelt_collected
    if _gdelt_collected:
        return []
    _gdelt_collected = True
    broad_query = {
        "name": "GDELT consolidated Baltic watch",
        "query": (
            "(Latvia OR Lithuania OR Estonia OR Baltic OR Kaliningrad OR Pskov OR Belarus) "
            "(drone OR missile OR sabotage OR explosion OR cyberattack OR infrastructure OR "
            "deployment OR readiness OR airspace OR GNSS OR jamming OR NATO)"
        ),
    }
    return _original_gdelt(session, broad_query, config, errors)


core.collect_gdelt = _collect_gdelt


# Bluesky moved unauthenticated search away from public.api.bsky.app in 2026.
def _collect_bluesky(session: Any, query: str, config: dict[str, Any], errors: list[str]) -> list[Any]:
    now = core.utcnow()
    try:
        response = core.request(
            session,
            "https://api.bsky.app/xrpc/app.bsky.feed.searchPosts",
            params={"q": query, "limit": 75, "sort": "latest"},
        )
        payload = response.json()
        items: list[Any] = []
        for post in payload.get("posts", []):
            record = post.get("record", {}) or {}
            text = core.strip_markup(str(record.get("text", "")))
            if not text:
                continue
            handle = str((post.get("author", {}) or {}).get("handle", "unknown"))
            uri = str(post.get("uri", ""))
            rkey = uri.rsplit("/", 1)[-1] if "/" in uri else ""
            link = f"https://bsky.app/profile/{handle}/post/{rkey}" if rkey else "https://bsky.app"
            published = core.parse_datetime(record.get("createdAt") or post.get("indexedAt"), now)
            title = text[:180] + ("…" if len(text) > 180 else "")
            items.append(
                core.Item(
                    title, link, f"Bluesky @{handle}", "bsky.app",
                    core.iso(published), core.iso(now), "social", 4, text, query,
                )
            )
        return items
    except Exception as exc:
        errors.append(f"Bluesky {query}: {type(exc).__name__}: {exc}")
        return []


core.collect_bluesky = _collect_bluesky


# Make the report distinguish an elevated collection priority from evidence that
# either hypothesis is currently true.
_original_build_report = core.build_report


def _build_report(*args: Any, **kwargs: Any) -> str:
    report = _original_build_report(*args, **kwargs)
    marker = "**Meeting phase:**"
    insertion = (
        "**Collection priority:** ELEVATED — the current diplomatic anomaly and prior Baltic warnings justify hourly review; "
        "this is not an attack warning.  \n"
    )
    lines = report.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(marker):
            lines.insert(index + 1, insertion)
            break
    return "\n".join(lines)


core.build_report = _build_report


if __name__ == "__main__":
    raise SystemExit(core.main())
