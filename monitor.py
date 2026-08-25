#!/usr/bin/env python3
"""Hourly public-source warning monitor for Baltic escalation indicators.

The monitor does not infer the purpose of any classified or undisclosed mission.
It searches only public news/RSS/social commentary, scores observable indicators
against two explicit hypotheses, and requires corroboration before escalation.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote_plus, urlparse

import feedparser
import requests

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config" / "watch_config.json"
STATE_PATH = ROOT / "data" / "state.json"
REPORT_PATH = ROOT / "reports" / "latest.md"
USER_AGENT = "Baltic-OSINT-Watch/1.0 (+defensive public-source monitoring)"
REQUEST_TIMEOUT = 25

INDICATORS: list[dict[str, Any]] = [
    {
        "id": "H1-I01",
        "name": "Specific official or embassy imminent-threat warning",
        "severity": "critical",
        "weights": {"H1": 6.0, "H2": 0.5},
        "any": [
            r"authorized departure", r"ordered departure", r"shelter[- ]in[- ]place",
            r"credible (?:and specific )?threat", r"imminent (?:attack|threat|strike)",
            r"security alert", r"evacuat(?:e|ion)", r"avoid the area"
        ],
        "geo": [
            r"latvia", r"lithuania", r"estonia", r"baltic", r"riga", r"vilnius",
            r"tallinn", r"kaliningrad", r"poland", r"suwa[lł]ki"
        ]
    },
    {
        "id": "H1-I02",
        "name": "Emergency NATO consultation or crisis-response activation",
        "severity": "critical",
        "weights": {"H1": 5.5, "H2": 1.0},
        "any": [
            r"article 4", r"emergency (?:north atlantic council|nac|meeting|consultation)",
            r"crisis response", r"activate(?:d|s)? (?:the )?(?:nato )?response force",
            r"raise(?:d|s)? (?:military )?readiness", r"extraordinary meeting"
        ],
        "geo": [r"nato", r"baltic", r"latvia", r"lithuania", r"estonia", r"poland", r"kaliningrad"]
    },
    {
        "id": "H1-I03",
        "name": "Abrupt reinforcement of Baltic air/missile defence posture",
        "severity": "high",
        "weights": {"H1": 4.0, "H2": 0.5},
        "all_groups": [
            [r"combat air patrol", r"air defen[cs]e", r"awacs", r"aew&c", r"scrambl(?:e|ed|ing)", r"force protection", r"dispers(?:e|ed|al)"],
            [r"reinforc(?:e|ed|ement)", r"additional", r"surge", r"continuous", r"emergency", r"heightened", r"elevated", r"deploy(?:ed|ment)"]
        ],
        "geo": [r"baltic", r"latvia", r"lithuania", r"estonia", r"poland", r"kaliningrad", r"riga", r"vilnius", r"tallinn"]
    },
    {
        "id": "H1-I04",
        "name": "Unscheduled airspace or maritime closure on a relevant axis",
        "severity": "high",
        "weights": {"H1": 4.0, "H2": 0.25},
        "all_groups": [
            [r"notam", r"airspace (?:closure|closed|restriction)", r"temporary restricted area", r"navigation warning", r"navtex", r"maritime exclusion", r"flight restriction"],
            [r"unannounced", r"unscheduled", r"abrupt", r"emergency", r"short[- ]notice", r"immediate effect", r"without prior notice"]
        ],
        "geo": [r"kaliningrad", r"pskov", r"belarus", r"baltic sea", r"gulf of finland", r"grodno", r"vitebsk", r"luga", r"ostrov"]
    },
    {
        "id": "H1-I05",
        "name": "Unusual Russian western-axis force, launcher, logistics or EW movement",
        "severity": "critical",
        "weights": {"H1": 5.0, "H2": 0.5},
        "all_groups": [
            [r"deploy(?:ed|ment)", r"mov(?:e|ed|ement)", r"convoy", r"rail movement", r"ammunition train", r"dispers(?:e|ed|al)", r"alert status", r"combat readiness", r"mobilization", r"field hospital"],
            [r"missile", r"iskander", r"launcher", r"geran", r"shahed", r"drone unit", r"electronic warfare", r"air defen[cs]e", r"ammunition", r"fuel train", r"troops?"]
        ],
        "geo": [r"kaliningrad", r"pskov", r"luga", r"ostrov", r"leningrad", r"belarus", r"grodno", r"vitebsk", r"baltic fleet"],
        "exclude": [r"routine rotation", r"long[- ]planned exercise", r"scheduled exercise"]
    },
    {
        "id": "H1-I06",
        "name": "Surge or geographic expansion in GNSS/EW interference",
        "severity": "medium",
        "weights": {"H1": 2.5},
        "all_groups": [
            [r"gnss jamming", r"gps jamming", r"navigation interference", r"spoofing", r"electronic warfare"],
            [r"surge", r"sharp increase", r"expanded", r"widespread", r"unprecedented", r"new area", r"intensif(?:y|ied|ication)"]
        ],
        "geo": [r"baltic", r"latvia", r"lithuania", r"estonia", r"poland", r"gulf of finland", r"kaliningrad"]
    },
    {
        "id": "H1-I07",
        "name": "Confirmed or multiply reported drone/munition incursion",
        "severity": "high",
        "weights": {"H1": 4.5, "H2": 0.5},
        "all_groups": [
            [r"unidentified drone", r"drone incursion", r"drone crossed", r"airspace violation", r"shahed", r"geran", r"loitering munition", r"cruise missile"],
            [r"intercept(?:ed|ion)", r"shot down", r"entered airspace", r"crossed the border", r"detected", r"tracked", r"wreckage", r"debris"]
        ],
        "geo": [r"latvia", r"lithuania", r"estonia", r"baltic", r"riga", r"vilnius", r"tallinn", r"poland", r"suwa[lł]ki"]
    },
    {
        "id": "H1-I08",
        "name": "Kinetic or sabotage incident at Baltic critical infrastructure",
        "severity": "critical",
        "weights": {"H1": 6.0, "H2": 1.0},
        "all_groups": [
            [r"explosion", r"detonation", r"fire", r"arson", r"sabotage", r"attack", r"strike", r"blast"],
            [r"critical infrastructure", r"power plant", r"substation", r"interconnector", r"railway", r"rail line", r"port", r"airport", r"defen[cs]e factory", r"drone factory", r"ammunition plant", r"telecom", r"data center", r"undersea cable"]
        ],
        "geo": [r"latvia", r"lithuania", r"estonia", r"baltic", r"riga", r"vilnius", r"tallinn", r"poland"]
    },
    {
        "id": "H1-I09",
        "name": "Coordinated Russian attribution/retaliation narrative",
        "severity": "medium",
        "weights": {"H1": 3.0, "H2": 0.5},
        "any": [
            r"baltic (?:states?|countries?).{0,80}ukrain(?:e|ian).{0,80}(?:drone|attack|airspace)",
            r"ukrain(?:e|ian).{0,80}(?:from|through|using).{0,80}(?:baltic|latvia|lithuania|estonia)",
            r"legitimate target", r"retaliat(?:e|ion)", r"captured ukrainian drone",
            r"reconstructed ukrainian drone", r"false[- ]flag"
        ],
        "geo": [r"latvia", r"lithuania", r"estonia", r"baltic", r"poland", r"kaliningrad", r"nato"]
    },
    {
        "id": "H1-I10",
        "name": "Cyber or cyber-physical disruption of Baltic defence/critical infrastructure",
        "severity": "high",
        "weights": {"H1": 3.5, "H2": 0.5},
        "all_groups": [
            [r"cyberattack", r"cyber attack", r"ddos", r"ransomware", r"intrusion", r"malware", r"wiper", r"scada", r"operational technology", r"industrial control"],
            [r"critical infrastructure", r"energy", r"power", r"rail", r"port", r"airport", r"telecom", r"defen[cs]e industr", r"government network"]
        ],
        "geo": [r"latvia", r"lithuania", r"estonia", r"baltic", r"riga", r"vilnius", r"tallinn", r"poland"]
    },
    {
        "id": "H1-I11",
        "name": "Abrupt Baltic civil-defence, border or reserve measures",
        "severity": "high",
        "weights": {"H1": 4.0, "H2": 0.5},
        "any": [
            r"border crossing.{0,40}closed", r"reserve call[- ]up", r"mobiliz(?:e|ed|ation).{0,40}(?:national guard|defen[cs]e league|reserve)",
            r"civil defen[cs]e alert", r"air[- ]raid sirens?", r"emergency services.{0,40}staged", r"public warning system activated"
        ],
        "geo": [r"latvia", r"lithuania", r"estonia", r"baltic", r"riga", r"vilnius", r"tallinn", r"poland"]
    },
    {
        "id": "H2-I01",
        "name": "Explicit Russian rejection of a U.S. warning or failed talks",
        "severity": "critical",
        "weights": {"H2": 6.0, "H1": 1.5},
        "any": [
            r"rejected.{0,80}warning", r"dismissed.{0,80}warning", r"refused.{0,80}assurance",
            r"no agreement", r"talks failed", r"negotiations failed", r"ultimatum.{0,40}rejected",
            r"warning.{0,40}ignored", r"failed to reach"
        ],
        "subject": [r"ratcliffe", r"cia director", r"cia chief", r"u\.s\. delegation", r"us delegation", r"moscow talks"]
    },
    {
        "id": "H2-I02",
        "name": "Hostile post-meeting readout or threatened consequences",
        "severity": "high",
        "weights": {"H2": 3.5, "H1": 1.0},
        "all_groups": [
            [r"unacceptable", r"consequences", r"red line", r"will respond", r"retaliation", r"grave mistake", r"no compromise"],
            [r"ratcliffe", r"cia director", r"cia chief", r"u\.s\. delegation", r"us delegation", r"moscow meeting", r"talks"]
        ]
    },
    {
        "id": "H2-I03",
        "name": "Immediate U.S./NATO protective escalation after the visit",
        "severity": "critical",
        "weights": {"H2": 5.0, "H1": 3.0},
        "all_groups": [
            [r"after ratcliffe", r"following ratcliffe", r"after the moscow (?:visit|meeting|talks)", r"following the moscow (?:visit|meeting|talks)"],
            [r"security alert", r"ordered departure", r"reinforced", r"heightened readiness", r"emergency meeting", r"article 4", r"force protection", r"air defen[cs]e"]
        ]
    },
    {
        "id": "H2-I04",
        "name": "Emergency public disclosure or allied sharing of specific intelligence",
        "severity": "high",
        "weights": {"H2": 4.0, "H1": 3.0},
        "all_groups": [
            [r"declassified intelligence", r"publicly released intelligence", r"shared intelligence with allies", r"specific intelligence", r"intelligence warning"],
            [r"russia", r"moscow", r"baltic", r"latvia", r"lithuania", r"estonia", r"nato"]
        ]
    },
    {
        "id": "H2-I05",
        "name": "Operational acceleration immediately after Ratcliffe departs",
        "severity": "critical",
        "weights": {"H2": 5.5, "H1": 3.5},
        "all_groups": [
            [r"hours after", r"shortly after", r"within hours", r"following ratcliffe['’]s departure", r"after ratcliffe left"],
            [r"drone", r"missile", r"attack", r"deployment", r"mobilization", r"airspace violation", r"sabotage", r"cyberattack"]
        ],
        "geo": [r"latvia", r"lithuania", r"estonia", r"baltic", r"kaliningrad", r"poland"]
    },
    {
        "id": "H2-I06",
        "name": "Departure with no readout (weak, non-diagnostic)",
        "severity": "low",
        "weights": {"H2": 1.0},
        "all_groups": [
            [r"departed moscow", r"left moscow", r"returned from moscow", r"c-17.{0,80}(?:departed|left)"],
            [r"no comment", r"no readout", r"declined to comment", r"purpose remains unclear", r"without a statement"]
        ],
        "subject": [r"ratcliffe", r"cia director", r"cia chief", r"u\.s\. delegation", r"us delegation", r"c-17"]
    },
    {
        "id": "D-I01",
        "name": "Official assessment says no imminent Baltic threat",
        "severity": "disconfirming",
        "weights": {"H1": -3.0},
        "any": [
            r"no (?:direct|specific|immediate|imminent) threat", r"no indication.{0,60}imminent",
            r"risk of a conventional attack.{0,30}(?:remains|is) low", r"no intention.{0,50}attack"
        ],
        "geo": [r"latvia", r"lithuania", r"estonia", r"baltic", r"nato"]
    },
    {
        "id": "D-I02",
        "name": "Activity explicitly identified as long-planned/routine exercise",
        "severity": "disconfirming",
        "weights": {"H1": -2.0},
        "all_groups": [
            [r"planned exercise", r"long[- ]planned", r"scheduled exercise", r"routine exercise", r"announced in advance"],
            [r"kaliningrad", r"baltic", r"latvia", r"lithuania", r"estonia", r"poland", r"nato"]
        ]
    },
    {
        "id": "D-I03",
        "name": "Drone attributed to Ukrainian origin/spillover rather than deliberate Russian strike",
        "severity": "disconfirming",
        "weights": {"H1": -2.0},
        "all_groups": [
            [r"ukrainian origin", r"originated in ukraine", r"ukrainian drone", r"diverted by.{0,30}(?:jamming|electronic warfare)", r"accidental spillover", r"stray drone"],
            [r"latvia", r"lithuania", r"estonia", r"baltic", r"poland"]
        ]
    },
    {
        "id": "D-I04",
        "name": "Follow-on dialogue or concrete de-escalation after meeting",
        "severity": "disconfirming",
        "weights": {"H2": -3.0},
        "all_groups": [
            [r"agreed to continue talks", r"follow[- ]up meeting", r"hotline", r"de[- ]escalation", r"mutual assurance", r"confidence[- ]building measure"],
            [r"ratcliffe", r"cia director", r"cia chief", r"moscow", r"u\.s\.-russia", r"us-russia"]
        ]
    }
]

@dataclass
class Item:
    title: str
    url: str
    source: str
    domain: str
    published: str
    collected: str
    channel: str
    tier: int
    text: str
    query: str = ""

    def fingerprint(self) -> str:
        normalized = re.sub(r"\W+", " ", self.title.lower()).strip()
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:24]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_datetime(value: Any, fallback: datetime | None = None) -> datetime:
    fallback = fallback or utcnow()
    if value is None:
        return fallback
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value).strip()
        if not raw:
            return fallback
        dt = None
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
        if dt is None:
            try:
                dt = parsedate_to_datetime(raw)
            except (TypeError, ValueError, OverflowError):
                pass
        if dt is None:
            try:
                dt = datetime.strptime(raw, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            except ValueError:
                return fallback
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def strip_markup(value: str) -> str:
    value = html.unescape(value or "")
    value = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().removeprefix("www.")
    except Exception:
        return ""


def source_tier(domain: str, channel: str, config: dict[str, Any], explicit: int | None = None) -> int:
    if explicit:
        return explicit
    domain = domain.lower()
    if any(domain == d or domain.endswith("." + d) for d in config["official_domains"]):
        return 1
    if any(domain == d or domain.endswith("." + d) for d in config["high_reliability_domains"]):
        return 2
    if channel == "social":
        return 4
    return 3


def request(session: requests.Session, url: str, *, params: dict[str, Any] | None = None) -> requests.Response:
    response = session.get(url, params=params, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
    response.raise_for_status()
    return response


def collect_feed(session: requests.Session, name: str, url: str, config: dict[str, Any], explicit_tier: int | None, errors: list[str]) -> list[Item]:
    now = utcnow()
    try:
        response = request(session, url)
        parsed = feedparser.parse(response.content)
        items: list[Item] = []
        for entry in parsed.entries[: config["max_items_per_source"]]:
            link = str(entry.get("link", "")).strip()
            title = strip_markup(str(entry.get("title", "")))
            summary = strip_markup(str(entry.get("summary", entry.get("description", ""))))
            if not title or not link:
                continue
            published = parse_datetime(entry.get("published") or entry.get("updated"), now)
            domain = domain_of(link)
            items.append(Item(title, link, name, domain, iso(published), iso(now), "rss", source_tier(domain, "rss", config, explicit_tier), f"{title}. {summary}"))
        return items
    except Exception as exc:
        errors.append(f"RSS {name}: {type(exc).__name__}: {exc}")
        return []


def collect_google_news(session: requests.Session, query: dict[str, str], config: dict[str, Any], errors: list[str]) -> list[Item]:
    now = utcnow()
    q = f"{query['query']} when:1d"
    url = "https://news.google.com/rss/search?" + f"q={quote_plus(q)}&hl=en-US&gl=US&ceid=US:en"
    try:
        response = request(session, url)
        parsed = feedparser.parse(response.content)
        items: list[Item] = []
        for entry in parsed.entries[: config["max_items_per_source"]]:
            title = strip_markup(str(entry.get("title", "")))
            link = str(entry.get("link", "")).strip()
            if not title or not link:
                continue
            source_info = entry.get("source", {}) or {}
            source_name = strip_markup(str(source_info.get("title", "Google News")))
            source_url = str(source_info.get("href", ""))
            publisher_domain = domain_of(source_url)
            published = parse_datetime(entry.get("published") or entry.get("updated"), now)
            summary = strip_markup(str(entry.get("summary", "")))
            items.append(Item(title, link, source_name, publisher_domain or domain_of(link), iso(published), iso(now), "news", source_tier(publisher_domain, "news", config), f"{title}. {summary}", query["name"]))
        return items
    except Exception as exc:
        errors.append(f"Google News {query['name']}: {type(exc).__name__}: {exc}")
        return []


def collect_gdelt(session: requests.Session, query: dict[str, str], config: dict[str, Any], errors: list[str]) -> list[Item]:
    now = utcnow()
    params = {"query": query["query"], "mode": "ArtList", "maxrecords": min(100, config["max_items_per_source"]), "format": "json", "timespan": "1d", "sort": "DateDesc"}
    try:
        response = request(session, "https://api.gdeltproject.org/api/v2/doc/doc", params=params)
        payload = response.json()
        items: list[Item] = []
        for article in payload.get("articles", []):
            title = strip_markup(str(article.get("title", "")))
            link = str(article.get("url", "")).strip()
            if not title or not link:
                continue
            domain = str(article.get("domain") or domain_of(link)).lower()
            published = parse_datetime(article.get("seendate"), now)
            items.append(Item(title, link, domain or "GDELT", domain, iso(published), iso(now), "news", source_tier(domain, "news", config), title, query["name"]))
        return items
    except Exception as exc:
        errors.append(f"GDELT {query['name']}: {type(exc).__name__}: {exc}")
        return []


def collect_bluesky(session: requests.Session, query: str, config: dict[str, Any], errors: list[str]) -> list[Item]:
    now = utcnow()
    try:
        response = request(session, "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts", params={"q": query, "limit": 75, "sort": "latest"})
        payload = response.json()
        items: list[Item] = []
        for post in payload.get("posts", []):
            record = post.get("record", {}) or {}
            text = strip_markup(str(record.get("text", "")))
            if not text:
                continue
            handle = str((post.get("author", {}) or {}).get("handle", "unknown"))
            uri = str(post.get("uri", ""))
            rkey = uri.rsplit("/", 1)[-1] if "/" in uri else ""
            link = f"https://bsky.app/profile/{handle}/post/{rkey}" if rkey else "https://bsky.app"
            published = parse_datetime(record.get("createdAt") or post.get("indexedAt"), now)
            title = text[:180] + ("…" if len(text) > 180 else "")
            items.append(Item(title, link, f"Bluesky @{handle}", "bsky.app", iso(published), iso(now), "social", 4, text, query))
        return items
    except Exception as exc:
        errors.append(f"Bluesky {query}: {type(exc).__name__}: {exc}")
        return []


def regex_any(patterns: Iterable[str], text: str) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL) for pattern in patterns)


def match_indicator(text: str, rule: dict[str, Any]) -> bool:
    if rule.get("exclude") and regex_any(rule["exclude"], text):
        return False
    if rule.get("any") and not regex_any(rule["any"], text):
        return False
    if rule.get("geo") and not regex_any(rule["geo"], text):
        return False
    if rule.get("subject") and not regex_any(rule["subject"], text):
        return False
    return all(regex_any(group, text) for group in rule.get("all_groups", []))


def item_indicator_hits(item: Item) -> list[dict[str, Any]]:
    text = f"{item.title}. {item.text}"
    hits: list[dict[str, Any]] = []
    multiplier = {1: 1.15, 2: 1.0, 3: 0.72, 4: 0.42}.get(item.tier, 0.6)
    for rule in INDICATORS:
        if match_indicator(text, rule):
            hits.append({"id": rule["id"], "name": rule["name"], "severity": rule["severity"], "weights": {hyp: round(float(weight) * multiplier, 2) for hyp, weight in rule["weights"].items()}})
    return hits


def dedupe_items(items: list[Item]) -> list[Item]:
    chosen: dict[str, Item] = {}
    for item in items:
        key = item.fingerprint()
        current = chosen.get(key)
        if current is None or item.tier < current.tier:
            chosen[key] = item
    return list(chosen.values())


def is_relevant_age(item: Item, now: datetime, hours: int) -> bool:
    published = parse_datetime(item.published, now)
    return now - timedelta(hours=hours) <= published <= now + timedelta(hours=2)


def observation_from_item(item: Item, hits: list[dict[str, Any]]) -> dict[str, Any]:
    return {"fingerprint": item.fingerprint(), "title": item.title, "url": item.url, "source": item.source, "domain": item.domain or item.source, "published": item.published, "collected": item.collected, "channel": item.channel, "tier": item.tier, "query": item.query, "hits": hits}


def update_meeting_phase(state: dict[str, Any], observations: list[dict[str, Any]]) -> str:
    phase = state.get("meeting_phase", "ongoing")
    departure = re.compile(r"departed moscow|left moscow|returned from moscow|c-17.{0,80}(?:departed|left)", re.I | re.S)
    subject = re.compile(r"ratcliffe|cia director|cia chief|u\.s\. delegation|us delegation|c-17", re.I)
    for obs in observations:
        if departure.search(obs["title"]) and subject.search(obs["title"]) and obs.get("tier", 4) <= 2:
            phase = "post-visit"
            break
    state["meeting_phase"] = phase
    return phase


def indicator_rollup(observations: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    rollup: dict[str, dict[str, Any]] = {}
    for obs in observations:
        for hit in obs.get("hits", []):
            rec = rollup.setdefault(hit["id"], {"id": hit["id"], "name": hit["name"], "severity": hit["severity"], "count": 0, "domains": set(), "best_tier": 9})
            rec["count"] += 1
            rec["domains"].add(obs.get("domain") or obs.get("source"))
            rec["best_tier"] = min(rec["best_tier"], int(obs.get("tier", 4)))
    return rollup


def score_hypothesis(observations: list[dict[str, Any]], hypothesis: str, now: datetime) -> dict[str, Any]:
    contributions: list[dict[str, Any]] = []
    positive_domains: set[str] = set()
    reliable_domains: set[str] = set()
    critical_positive = 0
    official_critical = False
    for obs in observations:
        age_hours = max(0.0, (now - parse_datetime(obs["published"], now)).total_seconds() / 3600)
        decay = 1.0 if age_hours <= 6 else 0.72 if age_hours <= 24 else 0.42
        hit_weights = [float(h["weights"].get(hypothesis, 0.0)) for h in obs.get("hits", []) if hypothesis in h.get("weights", {})]
        if not hit_weights:
            continue
        positives = sorted((w for w in hit_weights if w > 0), reverse=True)
        negatives = sorted((w for w in hit_weights if w < 0))
        positive = (positives[0] if positives else 0.0) + 0.25 * sum(positives[1:3])
        value = (positive + sum(negatives[:2])) * decay
        if value == 0:
            continue
        contributions.append({"value": value, "obs": obs})
        if value > 0:
            domain = obs.get("domain") or obs.get("source")
            positive_domains.add(domain)
            if int(obs.get("tier", 4)) <= 2:
                reliable_domains.add(domain)
            critical_hits = [h for h in obs.get("hits", []) if h.get("severity") == "critical" and h.get("weights", {}).get(hypothesis, 0) > 0]
            if critical_hits:
                critical_positive += 1
                if int(obs.get("tier", 4)) == 1:
                    official_critical = True
    positives = sorted((c for c in contributions if c["value"] > 0), key=lambda c: c["value"], reverse=True)
    negatives = sorted((c for c in contributions if c["value"] < 0), key=lambda c: c["value"])
    diminishing = [1.0, 0.68, 0.48, 0.34, 0.24, 0.18, 0.14, 0.10]
    raw_positive = sum(c["value"] * diminishing[min(i, len(diminishing) - 1)] for i, c in enumerate(positives[:12]))
    raw_negative = sum(c["value"] * 0.55 for c in negatives[:5])
    bonus = (0.6 if len(positive_domains) >= 2 else 0.0) + (0.5 if len(positive_domains) >= 3 else 0.0) + (0.5 if len(reliable_domains) >= 2 else 0.0)
    score = round(max(0.0, min(10.0, raw_positive + raw_negative + bonus)), 1)
    if score >= 8.0 and (official_critical or (len(positive_domains) >= 3 and critical_positive >= 2)):
        level = "RED"
    elif (score >= 5.0 and official_critical) or (score >= 6.0 and len(positive_domains) >= 2 and len(reliable_domains) >= 1):
        level = "ORANGE"
    elif score >= 3.0:
        level = "AMBER"
    else:
        level = "GREEN"
    if positive_domains and not reliable_domains and level in {"ORANGE", "RED"}:
        level, score = "AMBER", min(score, 5.0)
    return {"score": score, "level": level, "positive_domains": sorted(positive_domains), "reliable_domains": sorted(reliable_domains), "critical_positive": critical_positive, "official_critical": official_critical, "top": [c["obs"] for c in positives[:12]]}


def highest_level(h1: dict[str, Any], h2: dict[str, Any]) -> str:
    order = {"GREEN": 0, "AMBER": 1, "ORANGE": 2, "RED": 3}
    return max((h1["level"], h2["level"]), key=lambda value: order[value])


def escape_md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def build_report(now: datetime, phase: str, new_observations: list[dict[str, Any]], observations: list[dict[str, Any]], h1: dict[str, Any], h2: dict[str, Any], errors: list[str], source_count: int) -> str:
    overall = highest_level(h1, h2)
    rollup = indicator_rollup(observations)
    h2_qualifier = "provisional while the visit is ongoing" if phase == "ongoing" else "post-visit assessment"
    lines = [
        "# Baltic OSINT Watch — Current Assessment", "", f"**Generated:** {iso(now)}  ", f"**Meeting phase:** {phase}  ",
        f"**Overall watch condition:** {overall}  ",
        f"**H1 — visit concerned a near-term Baltic attack/provocation:** {h1['level']} ({h1['score']}/10 indicator score)  ",
        f"**H2 — warning/deconfliction effort failed:** {h2['level']} ({h2['score']}/10 indicator score; {h2_qualifier})", "",
        "> This is a public-source indicator monitor, not a probability estimate and not an inference about the purpose of an undisclosed U.S. government mission. A score reflects observable warning signatures, source quality, recency and corroboration.", "",
        "## Collection summary", "", f"- New unique items this run: **{len(new_observations)}**", f"- Rolling observations retained (72 hours): **{len(observations)}**", f"- Raw items collected before deduplication: **{source_count}**", f"- Collection errors: **{len(errors)}**", "",
        "## Triggered indicators (rolling 72 hours)", "", "| ID | Indicator | Severity | Hits | Independent domains | Best source tier |", "|---|---|---:|---:|---:|---:|"
    ]
    triggered = sorted(rollup.values(), key=lambda rec: (0 if rec["severity"] == "critical" else 1 if rec["severity"] == "high" else 2, -rec["count"]))
    if not triggered:
        lines.append("| — | No configured indicator matched | — | 0 | 0 | — |")
    else:
        for rec in triggered:
            lines.append(f"| {rec['id']} | {escape_md(rec['name'])} | {rec['severity']} | {rec['count']} | {len(rec['domains'])} | {rec['best_tier']} |")
    lines.extend(["", "## New items that triggered indicators", ""])
    relevant_new = sorted((obs for obs in new_observations if obs.get("hits")), key=lambda obs: (obs.get("tier", 4), obs.get("published", "")))
    if not relevant_new:
        lines.append("No newly collected item triggered a configured indicator.")
    else:
        for obs in relevant_new[:30]:
            hit_ids = ", ".join(hit["id"] for hit in obs["hits"])
            lines.append(f"- **[{escape_md(obs['title'])}]({obs['url']})** — {escape_md(obs['source'])}; tier {obs['tier']}; {obs['published']}; indicators: {hit_ids}")
    lines.extend(["", "## Escalation logic", "", "- **AMBER** may be produced by one meaningful but uncorroborated indicator. It is a collection cue, not a warning of attack.", "- **ORANGE** requires a high aggregate score plus at least two independent domains and at least one official/high-reliability source, unless a direct official critical warning is observed.", "- **RED** requires either a direct official critical indicator or a multi-source cluster containing at least two critical indicators. Social-only reporting is capped at AMBER.", "- Silence, Kremlin denial, secrecy, a C-17/C-40 movement, or departure without a readout do not independently establish either hypothesis.", "", "## Collection health", ""])
    lines.extend((f"- {escape_md(error)}" for error in errors[:30]) if errors else ["All configured collectors returned without an exception."])
    lines.append("")
    return "\n".join(lines)[:60000]


def github_request(method: str, path: str, token: str, payload: dict[str, Any] | None = None) -> requests.Response:
    response = requests.request(method, f"https://api.github.com{path}", headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": USER_AGENT}, json=payload, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response


def update_status_issue(report: str, overall: str, state: dict[str, Any]) -> None:
    token = os.getenv("GITHUB_TOKEN", "").strip()
    repository = os.getenv("GITHUB_REPOSITORY", "").strip()
    if not token or not repository:
        print("GitHub issue update skipped: GITHUB_TOKEN or GITHUB_REPOSITORY missing")
        return
    owner = repository.split("/", 1)[0]
    title = "[Baltic OSINT Watch] Current assessment"
    try:
        issues = github_request("GET", f"/repos/{repository}/issues?state=open&per_page=100", token).json()
        current = next((issue for issue in issues if issue.get("title") == title and "pull_request" not in issue), None)
        payload = {"title": title, "body": report, "assignees": [owner]}
        if current:
            if current.get("body") != report:
                github_request("PATCH", f"/repos/{repository}/issues/{current['number']}", token, payload)
        else:
            github_request("POST", f"/repos/{repository}/issues", token, payload)
        if overall in {"ORANGE", "RED"} and state.get("last_alert_level") != overall:
            alert_title = f"[{overall}] Baltic OSINT Watch escalation — {utcnow().strftime('%Y-%m-%d %H:%MZ')}"
            github_request("POST", f"/repos/{repository}/issues", token, {"title": alert_title, "body": report, "assignees": [owner]})
            state["last_alert_level"], state["last_alert_at"] = overall, iso(utcnow())
        elif overall in {"GREEN", "AMBER"}:
            state["last_alert_level"] = overall
    except Exception as exc:
        print(f"GitHub issue update failed: {type(exc).__name__}: {exc}", file=sys.stderr)


def main() -> int:
    now = utcnow()
    config = load_json(CONFIG_PATH, {})
    if not config:
        print(f"Missing or invalid configuration: {CONFIG_PATH}", file=sys.stderr)
        return 2
    state = load_json(STATE_PATH, {"meeting_phase": "ongoing", "observations": [], "seen": {}})
    state.setdefault("observations", [])
    state.setdefault("seen", {})
    session = requests.Session()
    errors: list[str] = []
    items: list[Item] = []
    for feed in config["rss_feeds"]:
        items.extend(collect_feed(session, feed["name"], feed["url"], config, feed.get("tier"), errors))
    for query in config["queries"]:
        items.extend(collect_google_news(session, query, config, errors))
        items.extend(collect_gdelt(session, query, config, errors))
        time.sleep(0.15)
    for query in config.get("bluesky_queries", []):
        items.extend(collect_bluesky(session, query, config, errors))
        time.sleep(0.15)
    raw_count = len(items)
    items = [item for item in dedupe_items(items) if is_relevant_age(item, now, int(config["lookback_hours"]))]
    new_observations: list[dict[str, Any]] = []
    for item in items:
        fingerprint = item.fingerprint()
        if fingerprint in state["seen"]:
            continue
        obs = observation_from_item(item, item_indicator_hits(item))
        new_observations.append(obs)
        state["seen"][fingerprint] = item.published
    cutoff = now - timedelta(hours=int(config["lookback_hours"]))
    observations = [obs for obs in state["observations"] if parse_datetime(obs.get("published"), now) >= cutoff]
    observations.extend(new_observations)
    persisted: dict[str, dict[str, Any]] = {}
    for obs in observations:
        key = obs["fingerprint"]
        current = persisted.get(key)
        if current is None or int(obs.get("tier", 4)) < int(current.get("tier", 4)):
            persisted[key] = obs
    observations = sorted(persisted.values(), key=lambda obs: obs.get("published", ""), reverse=True)
    state["observations"] = observations
    seen_cutoff = now - timedelta(days=14)
    state["seen"] = {key: value for key, value in state["seen"].items() if parse_datetime(value, now) >= seen_cutoff}
    phase = update_meeting_phase(state, observations)
    h1, h2 = score_hypothesis(observations, "H1", now), score_hypothesis(observations, "H2", now)
    overall = highest_level(h1, h2)
    report = build_report(now, phase, new_observations, observations, h1, h2, errors, raw_count)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report + "\n", encoding="utf-8")
    state["last_run"] = iso(now)
    state["last_scores"] = {"H1": h1, "H2": h2, "overall": overall}
    update_status_issue(report, overall, state)
    save_json(STATE_PATH, state)
    print(report)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
