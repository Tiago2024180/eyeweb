"""
===========================================
Eye Web Backend — Traffic Monitoring Service
===========================================
Handles request logging, suspicious activity detection,
IP blocking, VPN/proxy detection, and geo-lookup.

Used by the traffic middleware (main.py) and
the traffic router (routers/traffic_router.py).
"""

import os
import time
import json
import logging
from collections import defaultdict
from typing import Dict, Optional

import httpx

logger = logging.getLogger(__name__)

# ─── PATHS TO SKIP (avoid feedback loops) ────────────
SKIP_PATHS = {"/docs", "/redoc", "/openapi.json", "/health"}
SKIP_PREFIXES = ("/api/admin/traffic", "/api/visit")

# ─── THREAT SIGNATURES ───────────────────────────────
SCANNER_AGENTS = [
    "nmap", "nikto", "sqlmap", "dirbuster", "gobuster",
    "wpscan", "masscan", "zmap", "shodan", "censys",
    "nuclei", "ffuf", "feroxbuster", "burpsuite", "hydra",
    "metasploit", "openvas", "nessus", "qualys", "acunetix",
]

SQL_PATTERNS = [
    "' or ", "' and ", "union select", "drop table",
    "insert into", "delete from", "1=1", "' or '1'='1",
    "char(", "concat(", "benchmark(", "sleep(",
    "waitfor delay", "pg_sleep", "load_file", "0x",
]

PATH_TRAVERSAL = ["../", "..\\", "%2e%2e", "%252e"]

# ─── THRESHOLDS ──────────────────────────────────────
RATE_LIMIT_WINDOW = 60       # seconds
RATE_LIMIT_MAX = 100         # requests per window
RATE_LIMIT_AUTOBLOCK = 200   # auto-block at 2x
BRUTE_FORCE_WINDOW = 300     # 5 minutes
BRUTE_FORCE_MAX = 10         # login attempts


class TrafficService:
    """
    Singleton service for traffic monitoring.
    
    - Logs every request to Supabase (fire-and-forget)
    - Tracks request rates per IP in memory
    - Detects suspicious patterns (scanners, SQLi, brute force, etc.)
    - Auto-blocks IPs that exceed thresholds
    - Geo-locates IPs and detects VPN/proxy
    - Caches geo data in Supabase + memory
    """

    _instance: Optional["TrafficService"] = None

    @classmethod
    def get(cls) -> "TrafficService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._url = os.getenv("SUPABASE_URL", "")
        self._key = os.getenv("SUPABASE_SERVICE_KEY", "")
        self._headers = {
            "apikey": self._key,
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        }
        # In-memory state
        self.blocked_ips: set = set()
        self._req_counts: Dict[str, list] = defaultdict(list)
        self._geo_cache: Dict[str, dict] = {}
        self._initialized = False

    @property
    def _configured(self) -> bool:
        return bool(self._url and self._key)

    # ═══════════════════════════════════════════════════
    # INITIALIZATION
    # ═══════════════════════════════════════════════════

    async def init(self):
        """Load blocked IPs from Supabase on startup."""
        if self._initialized or not self._configured:
            return
        await self._refresh_blocked()
        self._initialized = True
        logger.info(f"🛡️  Traffic monitor initialized ({len(self.blocked_ips)} IPs bloqueados)")

    async def _refresh_blocked(self):
        """Refresh blocked IPs cache from Supabase."""
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get(
                    f"{self._url}/rest/v1/traffic_blocked_ips?select=ip",
                    headers=self._headers, timeout=5.0,
                )
                if r.status_code == 200:
                    self.blocked_ips = {row["ip"] for row in r.json()}
        except Exception as e:
            logger.warning(f"Failed to load blocked IPs: {e}")

    # ═══════════════════════════════════════════════════
    # CORE — called by middleware
    # ═══════════════════════════════════════════════════

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def should_log(self, path: str) -> bool:
        if path in SKIP_PATHS:
            return False
        return not any(path.startswith(p) for p in SKIP_PREFIXES)

    async def safe_log_request(self, **kwargs):
        """Fire-and-forget wrapper — never raises exceptions."""
        try:
            await self._log_request(**kwargs)
        except Exception as e:
            logger.debug(f"Traffic log error (non-critical): {e}")

    async def _log_request(self, ip: str, method: str, path: str,
                           status_code: int, user_agent: str, response_time_ms: int):
        """Log a request and check for suspicious activity."""
        if not self._configured:
            return

        now = time.time()

        # ─── Track request rate (keep 5 min window) ───
        self._req_counts[ip].append(now)
        cutoff = now - 300
        self._req_counts[ip] = [t for t in self._req_counts[ip] if t > cutoff]

        # Cleanup stale IPs if memory grows too large
        if len(self._req_counts) > 5000:
            for k in list(self._req_counts.keys()):
                self._req_counts[k] = [t for t in self._req_counts[k] if t > cutoff]
                if not self._req_counts[k]:
                    del self._req_counts[k]

        # ─── Geo lookup (cached) ───
        geo = await self._geo_lookup(ip)

        # ─── Insert log to Supabase ───
        try:
            async with httpx.AsyncClient() as c:
                await c.post(
                    f"{self._url}/rest/v1/traffic_logs",
                    headers=self._headers,
                    json={
                        "ip": ip,
                        "method": method,
                        "path": path,
                        "status_code": status_code,
                        "user_agent": (user_agent or "")[:500],
                        "country": geo.get("country", ""),
                        "city": geo.get("city", ""),
                        "is_vpn": geo.get("is_vpn", False),
                        "vpn_provider": geo.get("provider", ""),
                        "response_time_ms": response_time_ms,
                    },
                    timeout=5.0,
                )
        except Exception:
            pass  # Fire-and-forget

        # ─── Suspicious detection ───
        await self._detect_suspicious(ip, method, path, user_agent, now)

    # ═══════════════════════════════════════════════════
    # SUSPICIOUS ACTIVITY DETECTION
    # ═══════════════════════════════════════════════════

    async def _detect_suspicious(self, ip: str, method: str, path: str,
                                  user_agent: str, now: float):
        """Detect attack patterns and auto-block if necessary."""
        events = []

        # 1. Rate limiting (>100 req/min)
        recent_60s = [t for t in self._req_counts.get(ip, []) if now - t < RATE_LIMIT_WINDOW]
        if len(recent_60s) > RATE_LIMIT_MAX:
            events.append({
                "ip": ip, "event": "rate_limit", "severity": "high",
                "details": f"{len(recent_60s)} requests em {RATE_LIMIT_WINDOW}s (limite: {RATE_LIMIT_MAX})",
                "path": path,
                "_auto_block": len(recent_60s) > RATE_LIMIT_AUTOBLOCK,
            })

        # 2. Scanner detection (known tools in User-Agent)
        ua_lower = (user_agent or "").lower()
        for scanner in SCANNER_AGENTS:
            if scanner in ua_lower:
                events.append({
                    "ip": ip, "event": "scanner", "severity": "high",
                    "details": f"Scanner detetado: {scanner}",
                    "path": path, "_auto_block": True,
                })
                break

        # 3. SQL Injection patterns in path or query
        check_str = path.lower() + " " + ua_lower
        for pattern in SQL_PATTERNS:
            if pattern in check_str:
                events.append({
                    "ip": ip, "event": "sql_injection", "severity": "critical",
                    "details": f"Padrão SQL injection detetado: {pattern}",
                    "path": path, "_auto_block": True,
                })
                break

        # 4. Path traversal attempts
        for pattern in PATH_TRAVERSAL:
            if pattern in path.lower():
                events.append({
                    "ip": ip, "event": "path_traversal", "severity": "critical",
                    "details": f"Tentativa de path traversal: {pattern}",
                    "path": path, "_auto_block": True,
                })
                break

        # 5. Brute force (multiple POSTs to auth endpoints)
        if method == "POST" and any(p in path for p in ["/login", "/auth/", "/signin", "/send-code", "/verify"]):
            login_key = f"_login_{ip}"
            self._req_counts[login_key].append(now)
            self._req_counts[login_key] = [
                t for t in self._req_counts[login_key]
                if now - t < BRUTE_FORCE_WINDOW
            ]
            if len(self._req_counts[login_key]) > BRUTE_FORCE_MAX:
                events.append({
                    "ip": ip, "event": "brute_force", "severity": "critical",
                    "details": f"{len(self._req_counts[login_key])} tentativas de login em 5 minutos",
                    "path": path, "_auto_block": True,
                })

        # ─── Process events ───
        for event in events:
            auto_block = event.pop("_auto_block", False)

            # Insert to suspicious table
            try:
                async with httpx.AsyncClient() as c:
                    await c.post(
                        f"{self._url}/rest/v1/traffic_suspicious",
                        headers=self._headers,
                        json=event, timeout=5.0,
                    )
            except Exception:
                pass

            # Auto-block if threshold exceeded
            if auto_block and ip not in self.blocked_ips:
                await self.block_ip(ip, f"Auto: {event['event']}", "system")

    # ═══════════════════════════════════════════════════
    # GEO / VPN LOOKUP
    # ═══════════════════════════════════════════════════

    async def _geo_lookup(self, ip: str) -> dict:
        """Get country, city, VPN status for an IP (with caching)."""
        # Skip local/private IPs
        if ip in ("127.0.0.1", "::1", "localhost") or ip.startswith(("192.168.", "10.", "172.")):
            return {"country": "Local", "city": "", "is_vpn": False, "provider": ""}

        # Memory cache
        if ip in self._geo_cache:
            return self._geo_cache[ip]

        # Cap cache size
        if len(self._geo_cache) > 10000:
            self._geo_cache.clear()

        # DB cache (traffic_vpn_cache table)
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get(
                    f"{self._url}/rest/v1/traffic_vpn_cache?ip=eq.{ip}&select=*",
                    headers=self._headers, timeout=3.0,
                )
                if r.status_code == 200 and r.json():
                    d = r.json()[0]
                    result = {
                        "country": d.get("country", ""),
                        "city": d.get("city", ""),
                        "is_vpn": d.get("is_vpn", False),
                        "provider": d.get("provider", ""),
                    }
                    self._geo_cache[ip] = result
                    return result
        except Exception:
            pass

        # External API: ip-api.com (free, 45 req/min)
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get(
                    f"http://ip-api.com/json/{ip}?fields=status,country,city,proxy,hosting,isp",
                    timeout=3.0,
                )
                if r.status_code == 200:
                    d = r.json()
                    if d.get("status") == "success":
                        is_vpn = d.get("proxy", False) or d.get("hosting", False)
                        result = {
                            "country": d.get("country", "Desconhecido"),
                            "city": d.get("city", ""),
                            "is_vpn": is_vpn,
                            "provider": d.get("isp", "") if is_vpn else "",
                        }
                        # Save to DB cache
                        try:
                            await c.post(
                                f"{self._url}/rest/v1/traffic_vpn_cache",
                                headers={**self._headers, "Prefer": "return=minimal,resolution=merge-duplicates"},
                                json={
                                    "ip": ip, "is_vpn": is_vpn,
                                    "provider": result["provider"],
                                    "country": result["country"],
                                    "city": result["city"],
                                },
                                timeout=3.0,
                            )
                        except Exception:
                            pass
                        self._geo_cache[ip] = result
                        return result
        except Exception:
            pass

        return {"country": "Desconhecido", "city": "", "is_vpn": False, "provider": ""}

    # ═══════════════════════════════════════════════════
    # BLOCK / UNBLOCK
    # ═══════════════════════════════════════════════════

    async def block_ip(self, ip: str, reason: str, blocked_by: str = "admin"):
        """Block an IP address and save a snapshot of its recent logs."""
        if not self._configured:
            return

        geo = self._geo_cache.get(ip, {})
        req_count = len(self._req_counts.get(ip, []))

        # Get log snapshot (last 20 requests from this IP)
        log_snapshot = ""
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get(
                    f"{self._url}/rest/v1/traffic_logs?ip=eq.{ip}&order=created_at.desc&limit=20&select=*",
                    headers={**self._headers, "Prefer": "return=representation"},
                    timeout=5.0,
                )
                if r.status_code == 200:
                    log_snapshot = json.dumps(r.json(), indent=2, default=str)
        except Exception:
            pass

        # Insert into blocked_ips (UPSERT)
        try:
            async with httpx.AsyncClient() as c:
                await c.post(
                    f"{self._url}/rest/v1/traffic_blocked_ips",
                    headers={**self._headers, "Prefer": "return=minimal,resolution=merge-duplicates"},
                    json={
                        "ip": ip,
                        "reason": reason,
                        "blocked_by": blocked_by,
                        "request_count": req_count,
                        "country": geo.get("country", ""),
                        "is_vpn": geo.get("is_vpn", False),
                        "log_snapshot": log_snapshot,
                    },
                    timeout=5.0,
                )
        except Exception as e:
            logger.warning(f"Failed to block IP {ip}: {e}")

        self.blocked_ips.add(ip)
        logger.info(f"🚫 IP bloqueado: {ip} — {reason} ({blocked_by})")

    async def unblock_ip(self, ip: str):
        """Unblock an IP address."""
        if not self._configured:
            return
        try:
            async with httpx.AsyncClient() as c:
                await c.delete(
                    f"{self._url}/rest/v1/traffic_blocked_ips?ip=eq.{ip}",
                    headers=self._headers, timeout=5.0,
                )
        except Exception as e:
            logger.warning(f"Failed to unblock IP {ip}: {e}")

        self.blocked_ips.discard(ip)
        logger.info(f"✅ IP desbloqueado: {ip}")
