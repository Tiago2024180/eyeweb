"""
===========================================
Eye Web Backend — Dependencies (Auth)
===========================================

FastAPI dependencies for route protection.
Verifies Supabase JWT token and admin email hash.
"""

import hashlib
import logging

import httpx
from fastapi import HTTPException, Request, status

from .config import get_settings

logger = logging.getLogger(__name__)

# Cache rápido de tokens verificados (evita chamar Supabase a cada request)
# { token_hash: { "email": str, "ts": float } }
_token_cache: dict[str, dict] = {}
_TOKEN_CACHE_TTL = 300  # 5 minutos


async def verify_admin(request: Request):
    """
    Dependency que verifica se o request vem de um admin autenticado.

    1. Extrai Bearer token do header Authorization
    2. Verifica o token com Supabase /auth/v1/user
    3. Compara SHA-256 do email com ADMIN_EMAIL_HASH(ES)

    Usado como dependency nos routers de admin (traffic, etc.)
    """
    import time

    settings = get_settings()

    # ─── Extrair token ────────────────────────────────
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticação não fornecido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header[7:]  # Remove "Bearer "

    # ─── Cache rápido (evita chamada HTTP a cada 5s no auto-refresh) ──
    token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
    cached = _token_cache.get(token_hash)
    if cached and (time.time() - cached["ts"]) < _TOKEN_CACHE_TTL:
        return {"email": cached["email"]}

    # ─── Verificar com Supabase ───────────────────────
    supabase_url = settings.SUPABASE_URL
    supabase_key = settings.SUPABASE_SERVICE_KEY or settings.SUPABASE_ANON_KEY

    if not supabase_url:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Supabase não configurado",
        )

    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{supabase_url}/auth/v1/user",
                headers={
                    "apikey": supabase_key,
                    "Authorization": f"Bearer {token}",
                },
                timeout=5.0,
            )

        if r.status_code != 200:
            logger.warning(f"🔒 Token inválido/expirado (status={r.status_code})")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido ou expirado",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user = r.json()
        email = (user.get("email") or "").lower().strip()

        if not email:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email não encontrado no token",
            )

        # ─── Verificar se é admin ─────────────────────
        email_hash = hashlib.sha256(email.encode()).hexdigest()

        admin_hashes: set[str] = set()
        if settings.ADMIN_EMAIL_HASHES:
            admin_hashes.update(
                h.strip() for h in settings.ADMIN_EMAIL_HASHES.split(",") if h.strip()
            )
        if settings.ADMIN_EMAIL_HASH:
            admin_hashes.add(settings.ADMIN_EMAIL_HASH.strip())

        if not admin_hashes:
            logger.error("🔒 ADMIN_EMAIL_HASH(ES) não configurado — acesso negado por segurança")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administradores não configurados",
            )

        if email_hash not in admin_hashes:
            logger.warning(f"🔒 Email não é admin: {email[:3]}***")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Acesso restrito a administradores",
            )

        # ─── Guardar em cache ─────────────────────────
        _token_cache[token_hash] = {"email": email, "ts": time.time()}

        # Limpar cache se crescer demais
        if len(_token_cache) > 100:
            cutoff = time.time() - _TOKEN_CACHE_TTL
            expired = [k for k, v in _token_cache.items() if v["ts"] < cutoff]
            for k in expired:
                del _token_cache[k]

        logger.info(f"🔓 Admin verificado: {email[:3]}***")
        return {"email": email}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"🔒 Erro ao verificar token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Erro ao verificar autenticação",
            headers={"WWW-Authenticate": "Bearer"},
        )
