"""
===========================================
Eye Web Backend — News Search Service
===========================================

Searches for cybersecurity news from multiple sources:
- 12 Security RSS feeds
- Google News RSS
- Bing News RSS
- GDELT Project API

Ported from the test-site Node.js implementation.
"""

import logging
import time
import asyncio
import re
from typing import Optional
from xml.etree import ElementTree as ET

import httpx

logger = logging.getLogger(__name__)

# ===========================================
# CONSTANTS
# ===========================================

REPORTS_TTL = 600  # 10 minutes cache (seconds)

RSS_FEEDS = [
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "TheRecord", "url": "https://therecord.media/feed/"},
    {"name": "KrebsOnSecurity", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "HIBP Blog", "url": "https://www.troyhunt.com/feed/"},
    {"name": "TheHackerNews", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/"},
    {"name": "TheRegisterSecurity", "url": "https://www.theregister.com/security/headlines.atom"},
    {"name": "ReutersTopNews", "url": "https://feeds.reuters.com/reuters/topNews"},
    {"name": "BBCTechnology", "url": "http://feeds.bbci.co.uk/news/technology/rss.xml"},
    {"name": "TheVerge", "url": "https://www.theverge.com/rss/index.xml"},
    {"name": "ArsTechnica", "url": "http://feeds.arstechnica.com/arstechnica/index"},
    {"name": "Wired", "url": "https://www.wired.com/feed/rss"},
]

SECURITY_TERMS = [
    "breach", "breached", "hacked", "hack", "data leak", "leak", "leaked",
    "ransomware", "malware", "phishing", "credential", "credentials",
    "vulnerability", "exploit", "zero-day", "exposed", "exposure",
    "data theft", "extortion",
]

# ===========================================
# CACHING
# ===========================================

_cache: dict = {}


def _get_cached(key: str, ttl: float = REPORTS_TTL) -> Optional[dict]:
    entry = _cache.get(key)
    if entry and (time.time() - entry["ts"]) < ttl:
        return entry["data"]
    return None


def _set_cache(key: str, data):
    _cache[key] = {"data": data, "ts": time.time()}


# ===========================================
# HELPERS
# ===========================================

def get_root_domain(hostname: str) -> str:
    host = (hostname or "").lower().lstrip("www.")
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def build_keywords(query: str, qtype: str = "domain") -> list[str]:
    raw = (query or "").strip().lower()
    if not raw:
        return []

    if qtype == "email" and "@" in raw:
        domain = raw.split("@")[-1]
        root = get_root_domain(domain)
        brand = root.split(".")[0]
        return list(dict.fromkeys([domain, root, brand]))

    if qtype in ("url",) or "://" in raw:
        try:
            from urllib.parse import urlparse
            u = urlparse(raw if "://" in raw else f"https://{raw}")
            root = get_root_domain(u.hostname or "")
            brand = root.split(".")[0]
            return list(dict.fromkeys([u.hostname or "", root, brand]))
        except Exception:
            pass

    if qtype == "domain":
        root = get_root_domain(raw)
        brand = root.split(".")[0]
        return list(dict.fromkeys([raw, root, brand]))

    return [raw]


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text or "")


# ===========================================
# RSS PARSING (XML)
# ===========================================

def _parse_rss_items(feed_name: str, xml_text: str) -> list[dict]:
    """Parse RSS 2.0 or Atom feed XML into normalised item dicts."""
    items = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return items

    # --- RSS 2.0 ---
    for channel in root.iter("channel"):
        for item in channel.iter("item"):
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub_date = (
                item.findtext("pubDate")
                or item.findtext("date")
                or ""
            ).strip()
            desc = (
                item.findtext("description")
                or item.findtext("summary")
                or ""
            ).strip()
            items.append({
                "title": title,
                "link": link,
                "pubDate": pub_date,
                "source": feed_name,
                "snippet": _strip_html(desc)[:400],
            })

    if items:
        return items

    # --- Atom ---
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    for entry in root.findall("atom:entry", ns):
        title_el = entry.find("atom:title", ns)
        title = (title_el.text if title_el is not None else "").strip()
        link_el = entry.find("atom:link", ns)
        link = (link_el.get("href", "") if link_el is not None else "").strip()
        updated = (entry.findtext("atom:updated", "", ns) or "").strip()
        summary_el = entry.find("atom:summary", ns)
        summary = (summary_el.text if summary_el is not None else "").strip()
        items.append({
            "title": title,
            "link": link,
            "pubDate": updated,
            "source": feed_name,
            "snippet": _strip_html(summary)[:400],
        })

    # Fallback: try without namespace
    if not items:
        for entry in root.iter("entry"):
            title_el = entry.find("title")
            title = (title_el.text if title_el is not None else "").strip()
            link_el = entry.find("link")
            link = (link_el.get("href", "") if link_el is not None else "").strip()
            updated = (entry.findtext("updated") or entry.findtext("published") or "").strip()
            summary_el = entry.find("summary")
            summary = (summary_el.text if summary_el is not None else "").strip()
            items.append({
                "title": title,
                "link": link,
                "pubDate": updated,
                "source": feed_name,
                "snippet": _strip_html(summary)[:400],
            })

    return items


def _parse_google_news_items(xml_text: str) -> list[dict]:
    """Parse Google News RSS which wraps real source info inside <source> tags."""
    items = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return items

    for channel in root.iter("channel"):
        for item_el in channel.iter("item"):
            title = (item_el.findtext("title") or "").strip()
            link = (item_el.findtext("link") or "").strip()
            pub_date = (item_el.findtext("pubDate") or "").strip()
            source_el = item_el.find("source")
            source_name = "Google News"
            if source_el is not None:
                source_name = (source_el.text or source_name).strip()
                src_url = source_el.get("url")
                if src_url:
                    link = src_url

            # Strip trailing " - Source" from title
            last_dash = title.rfind(" - ")
            if last_dash > 10:
                title = title[:last_dash].strip()

            desc = _strip_html(item_el.findtext("description") or "")[:400]
            items.append({
                "title": title,
                "link": link,
                "pubDate": pub_date,
                "source": source_name,
                "snippet": desc,
            })

    return items


# ===========================================
# FETCH SOURCES
# ===========================================

async def _fetch_rss_items() -> list[dict]:
    """Fetch all 12 RSS feeds and return merged items."""
    cache_key = "reports:rss_items"
    cached = _get_cached(cache_key)
    if cached is not None:
        return cached

    all_items: list[dict] = []

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        tasks = []
        for feed in RSS_FEEDS:
            tasks.append(_fetch_single_rss(client, feed["name"], feed["url"]))
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, list):
            all_items.extend(result)

    _set_cache(cache_key, all_items)
    return all_items


async def _fetch_single_rss(client: httpx.AsyncClient, name: str, url: str) -> list[dict]:
    try:
        resp = await client.get(url, headers={"User-Agent": "EyeWeb/2.0"})
        if resp.status_code != 200:
            return []
        return _parse_rss_items(name, resp.text)
    except Exception:
        return []


def _match_items(items: list[dict], keywords: list[str]) -> list[dict]:
    """Filter items that match keywords AND at least one security term."""
    kw = [k.lower() for k in keywords if len(k) >= 3]
    if not kw:
        return []

    seen: set = set()
    results: list[dict] = []

    for item in items:
        hay = f"{item.get('title', '')} {item.get('link', '')} {item.get('snippet', '')}".lower()
        matched_kw = [k for k in kw if k in hay]
        matched_signals = [t for t in SECURITY_TERMS if t in hay]

        if matched_kw and matched_signals:
            key = item.get("link") or item.get("title", "")
            if key and key not in seen:
                seen.add(key)
                results.append({
                    **item,
                    "reason": {
                        "matchedKeywords": matched_kw,
                        "matchedSignals": matched_signals,
                    },
                })
    return results[:8]


async def _fetch_google_news(query: str, qtype: str) -> list[dict]:
    """Search Google News RSS for cybersecurity articles about the given query."""
    keywords = build_keywords(query, qtype)
    brand = keywords[-1] if keywords else ""
    if not brand or len(brand) < 2:
        return []

    sec_terms = [
        "breach", "hack", '"data leak"', "ransomware", "phishing",
        '"cyber attack"', "vulnerability", "malware", "exposed",
    ]
    or_clause = " OR ".join(sec_terms)
    search_query = f'"{brand}" ({or_clause})'

    urls = [
        f"https://news.google.com/rss/search?q={_urlencode(search_query)}&hl=en-US&gl=US&ceid=US:en",
        f"https://news.google.com/rss/search?q={_urlencode(search_query)}&hl=pt-PT&gl=PT&ceid=PT:pt",
    ]

    all_items: list[dict] = []

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        for url in urls:
            try:
                resp = await client.get(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; DataBreachChecker/2.0)"},
                )
                if resp.status_code == 200:
                    all_items.extend(_parse_google_news_items(resp.text))
            except Exception:
                pass

    # Filter by keywords
    kw = [k.lower() for k in keywords if len(k) >= 2]
    seen: set = set()
    filtered: list[dict] = []
    for item in all_items:
        hay = f"{item.get('title','')} {item.get('snippet','')}".lower()
        key = (item.get("link") or item.get("title", "")).lower().rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        if any(k in hay for k in kw):
            matched_kw = [k for k in kw if k in hay]
            matched_signals = [t for t in SECURITY_TERMS if t in hay]
            filtered.append({
                **item,
                "reason": {
                    "matchedKeywords": matched_kw,
                    "matchedSignals": matched_signals,
                },
            })

    return filtered[:15]


async def _fetch_bing_news(query: str, qtype: str) -> list[dict]:
    """Search Bing News RSS for cybersecurity articles about the given query."""
    keywords = build_keywords(query, qtype)
    brand = keywords[-1] if keywords else ""
    if not brand or len(brand) < 2:
        return []

    search_query = f"{brand} data breach OR hack OR ransomware OR phishing OR vulnerability"
    url = f"https://www.bing.com/news/search?q={_urlencode(search_query)}&format=rss"

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; DataBreachChecker/2.0)"},
            )
            if resp.status_code != 200:
                return []
            items = _parse_rss_items("BingNews", resp.text)
    except Exception:
        return []

    kw = [k.lower() for k in keywords if len(k) >= 2]
    result: list[dict] = []
    for item in items:
        hay = f"{item.get('title','')} {item.get('snippet','')}".lower()
        if any(k in hay for k in kw):
            matched_kw = [k for k in kw if k in hay]
            matched_signals = [t for t in SECURITY_TERMS if t in hay]
            result.append({
                **item,
                "reason": {
                    "matchedKeywords": matched_kw,
                    "matchedSignals": matched_signals,
                },
            })

    return result[:10]


async def _fetch_gdelt(query: str, qtype: str) -> list[dict]:
    """Search GDELT Project API for cybersecurity articles."""
    keywords = build_keywords(query, qtype)
    kw = [k.lower() for k in keywords if len(k) >= 3]
    if not kw:
        return []

    topic_query = " OR ".join(f'"{k}"' for k in kw)
    signal_query = " OR ".join(f'"{t}"' for t in SECURITY_TERMS)
    full_query = f"({topic_query}) AND ({signal_query})"

    url = (
        f"https://api.gdeltproject.org/api/v2/doc/doc"
        f"?query={_urlencode(full_query)}&mode=ArtList&maxrecords=15&format=json&sort=DateDesc"
    )

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return []
            data = resp.json()
    except Exception:
        return []

    articles = data.get("articles") or []
    results: list[dict] = []
    for a in articles:
        title = a.get("title", "")
        link = a.get("url", "")
        pub_date = a.get("seendate", "")
        snippet = (a.get("extras", {}) or {}).get("description", "") or a.get("description", "")
        hay = f"{title} {link} {snippet}".lower()
        matched_kw = [k for k in kw if k in hay]
        matched_signals = [t for t in SECURITY_TERMS if t in hay]
        if matched_kw and matched_signals:
            results.append({
                "title": title,
                "link": link,
                "pubDate": pub_date,
                "source": "GDELT",
                "snippet": snippet,
                "reason": {
                    "matchedKeywords": matched_kw,
                    "matchedSignals": matched_signals,
                },
            })

    return results


def _urlencode(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


# ===========================================
# MAIN PUBLIC FUNCTION
# ===========================================

async def search_news(query: str, qtype: str = "domain", hf_token: str = "") -> dict:
    """
    Search cybersecurity news from all sources for the given query.

    Returns a dict matching the test-site response shape:
    {
        query, type, keywords, aiEnabled,
        sourcesSearched: { googleNews, bingNews, gdelt, securityRSS, huggingFaceAI },
        totalResults, results: [...]
    }
    """
    keywords = build_keywords(query, qtype)
    if not query or not keywords:
        return {"query": query, "type": qtype, "keywords": [], "totalResults": 0, "results": []}

    cache_key = f"reports:unverified:{qtype}:{query.lower()}"
    cached = _get_cached(cache_key)
    if cached is not None:
        return cached

    # Fetch all sources in parallel
    google_task = _fetch_google_news(query, qtype)
    bing_task = _fetch_bing_news(query, qtype)
    gdelt_task = _fetch_gdelt(query, qtype)
    rss_task = _fetch_rss_items()

    google, bing, gdelt, rss_all = await asyncio.gather(
        google_task, bing_task, gdelt_task, rss_task,
        return_exceptions=True,
    )

    # Handle exceptions gracefully
    google = google if isinstance(google, list) else []
    bing = bing if isinstance(bing, list) else []
    gdelt = gdelt if isinstance(gdelt, list) else []
    rss_all = rss_all if isinstance(rss_all, list) else []

    rss = _match_items(rss_all, keywords)

    # Merge & deduplicate (priority: Google → Bing → GDELT → RSS)
    merged: list[dict] = []
    seen: set = set()
    for item in [*google, *bing, *gdelt, *rss]:
        key = (item.get("link") or item.get("title", "")).lower().split("?")[0].split("#")[0]
        if key and key not in seen:
            seen.add(key)
            merged.append(item)

    ai_enabled = bool(hf_token)

    # AI classification is handled separately by hf_service — called in router

    payload = {
        "query": query,
        "type": qtype,
        "keywords": keywords,
        "aiEnabled": ai_enabled,
        "sourcesSearched": {
            "googleNews": len(google),
            "bingNews": len(bing),
            "gdelt": len(gdelt),
            "securityRSS": len(rss),
            "huggingFaceAI": ai_enabled,
        },
        "totalResults": len(merged),
        "results": merged[:20],
    }

    _set_cache(cache_key, payload)
    return payload
