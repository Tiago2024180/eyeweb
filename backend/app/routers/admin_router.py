"""
===========================================
Eye Web Backend — Admin MFA Router
===========================================
Endpoints para verificação MFA do administrador.
Usa TOTP com HMAC-SHA256 sincronizado com o programa local.
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any, List
import time
import hashlib
import hmac
import struct
import os
import asyncio
import httpx
from pathlib import Path

# Carregar .env automaticamente
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)

from ..config import get_settings

router = APIRouter(prefix="/admin", tags=["admin"])
settings = get_settings()


# ===========================================
# CONFIGURAÇÃO TOTP
# ===========================================

# Secret partilhado com o programa local (eyeweb_auth.py)
# DEVE SER IGUAL em ambos os lados!
# ATENÇÃO: Definir via variável de ambiente ADMIN_MFA_SECRET
TOTP_SECRET = os.getenv("ADMIN_MFA_SECRET", "")

# Configuração TOTP
TOTP_INTERVAL = 30  # segundos
TOTP_DIGITS = 6     # dígitos (igual ao Supabase OTP)
TOTP_WINDOW = 4     # Aceitar códigos dos últimos 4 intervalos (2 minutos)

# Admin email hash (verificação extra)
# ATENÇÃO: Definir via variável de ambiente ADMIN_EMAIL_HASH
ADMIN_EMAIL_HASH = os.getenv("ADMIN_EMAIL_HASH", "")


# ===========================================
# MODELOS
# ===========================================

class VerifyMFARequest(BaseModel):
    email: EmailStr
    code: str
    fingerprint: Optional[str] = None


class VerifyMFAResponse(BaseModel):
    success: bool
    message: str


# ===========================================
# FUNÇÕES TOTP
# ===========================================

def generate_totp(secret: str, digits: int = 10, interval: int = 30, offset: int = 0) -> str:
    """
    Gera um código TOTP usando HMAC-SHA256.
    
    Args:
        secret: String secreta partilhada
        digits: Número de dígitos do código
        interval: Intervalo de tempo em segundos
        offset: Offset de tempo (-1 para código anterior, +1 para próximo)
    
    Returns:
        Código TOTP de N dígitos
    """
    # Tempo atual em intervalos (com offset)
    timestamp = int(time.time() // interval) + offset
    
    # Converter timestamp para bytes (8 bytes, big-endian)
    time_bytes = struct.pack(">Q", timestamp)
    
    # Gerar HMAC-SHA256
    key = secret.encode('utf-8')
    hmac_hash = hmac.new(key, time_bytes, hashlib.sha256).digest()
    
    # Dynamic truncation (extrair 4 bytes do hash)
    offset_byte = hmac_hash[-1] & 0x0F
    truncated = struct.unpack(">I", hmac_hash[offset_byte:offset_byte + 4])[0] & 0x7FFFFFFF
    
    # Gerar código com N dígitos
    code = truncated % (10 ** digits)
    
    # Pad com zeros à esquerda se necessário
    return str(code).zfill(digits)


def verify_totp(code: str, secret: str = TOTP_SECRET, window: int = TOTP_WINDOW) -> bool:
    """
    Verifica se o código TOTP é válido.
    
    Aceita códigos do período atual e dos períodos adjacentes (window).
    
    Args:
        code: Código a verificar
        secret: Secret partilhado
        window: Número de períodos adjacentes a aceitar (default: 1)
    
    Returns:
        True se o código é válido
    """
    # Verificar código atual e adjacentes (para compensar dessincronização)
    for offset in range(-window, window + 1):
        expected_code = generate_totp(secret, TOTP_DIGITS, TOTP_INTERVAL, offset)
        if code == expected_code:
            return True
    
    return False


def is_admin_email(email: str) -> bool:
    """Verifica se o email é do admin via hash."""
    email_hash = hashlib.sha256(email.lower().strip().encode()).hexdigest()
    return email_hash == ADMIN_EMAIL_HASH


# ===========================================
# ENDPOINTS
# ===========================================

@router.post("/verify-mfa", response_model=VerifyMFAResponse)
async def verify_admin_mfa(request: VerifyMFARequest):
    """
    Verifica o código MFA do administrador.
    
    O código é gerado pelo programa local (eyeweb_auth.py) usando TOTP.
    
    - Código de 10 dígitos
    - Válido por 30 segundos
    - Aceita 1 período de margem (dessincronização)
    """
    email = request.email.lower().strip()
    code = request.code.strip()
    
    # Verificar se é email de admin
    if not is_admin_email(email):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este email não tem permissões de administrador."
        )
    
    # Validar formato do código
    if len(code) != TOTP_DIGITS or not code.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"O código deve ter {TOTP_DIGITS} dígitos numéricos."
        )
    
    # Verificar código TOTP (válido por 2 minutos)
    if not verify_totp(code, TOTP_SECRET, TOTP_WINDOW):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Código MFA inválido ou expirado."
        )
    
    # Código válido!
    return VerifyMFAResponse(
        success=True,
        message="Código MFA verificado com sucesso!"
    )


@router.get("/test-totp")
async def test_totp():
    """
    Endpoint de teste para verificar geração TOTP (apenas em desenvolvimento).
    
    Retorna o código TOTP atual para debug.
    """
    if not settings.DEBUG and settings.ENVIRONMENT != "development":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este endpoint só está disponível em desenvolvimento."
        )
    
    current_code = generate_totp(TOTP_SECRET, TOTP_DIGITS, TOTP_INTERVAL)
    time_remaining = TOTP_INTERVAL - (int(time.time()) % TOTP_INTERVAL)
    
    return {
        "current_code": current_code,
        "time_remaining": time_remaining,
        "interval": TOTP_INTERVAL,
        "digits": TOTP_DIGITS
    }


# ===========================================
# HEALTH CHECK - MONITOR DE SAÚDE
# ===========================================

class ServiceStatus(BaseModel):
    name: str
    status: str  # "online", "offline", "degraded", "unknown"
    response_time_ms: Optional[float] = None
    message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    category: Optional[str] = None  # Para agrupar serviços
    url: Optional[str] = None  # Link para verificar manualmente


class HealthCheckResponse(BaseModel):
    overall_status: str
    timestamp: str
    services: List[ServiceStatus]
    summary: Dict[str, int]
    categories: Dict[str, List[ServiceStatus]]


async def check_service(name: str, check_func, category: str = "Geral") -> ServiceStatus:
    """Wrapper para verificar um serviço com timeout."""
    start_time = time.time()
    try:
        result = await asyncio.wait_for(check_func(), timeout=10.0)
        response_time = (time.time() - start_time) * 1000
        return ServiceStatus(
            name=name,
            status=result.get("status", "online"),
            response_time_ms=round(response_time, 2),
            message=result.get("message"),
            details=result.get("details"),
            category=category,
            url=result.get("url")
        )
    except asyncio.TimeoutError:
        return ServiceStatus(
            name=name,
            status="offline",
            response_time_ms=10000,
            message="Timeout ao conectar ao serviço",
            category=category
        )
    except Exception as e:
        response_time = (time.time() - start_time) * 1000
        return ServiceStatus(
            name=name,
            status="offline",
            response_time_ms=round(response_time, 2),
            message=str(e),
            category=category
        )


# ===========================================
# VERIFICAÇÕES INDIVIDUAIS
# ===========================================

async def check_backend_api() -> Dict[str, Any]:
    """Verifica se o próprio backend está a responder."""
    return {
        "status": "online",
        "message": "API a funcionar normalmente",
        "details": {"version": "1.0.0", "environment": settings.ENVIRONMENT},
        "url": "http://localhost:8000/docs" if settings.ENVIRONMENT == "development" else "https://eye-web-api.onrender.com/docs"
    }


# --- SUPABASE (múltiplas verificações) ---

async def check_supabase_connection() -> Dict[str, Any]:
    """Verifica conexão básica com Supabase."""
    supabase_url = settings.SUPABASE_URL
    if not supabase_url:
        return {"status": "unknown", "message": "SUPABASE_URL não configurado"}
    
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{supabase_url}/rest/v1/", timeout=5.0)
        if response.status_code in [200, 401]:
            return {"status": "online", "message": "Conexão estabelecida", "url": "https://supabase.com/dashboard/project/zawqvduiuljlvquxzlpq"}
        return {"status": "degraded", "message": f"Status code: {response.status_code}", "url": "https://supabase.com/dashboard/project/zawqvduiuljlvquxzlpq"}


async def check_supabase_auth() -> Dict[str, Any]:
    """Verifica se o serviço de autenticação do Supabase está a funcionar."""
    supabase_url = settings.SUPABASE_URL
    if not supabase_url:
        return {"status": "unknown", "message": "SUPABASE_URL não configurado"}
    
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{supabase_url}/auth/v1/health", timeout=5.0)
        if response.status_code in [200, 401]:
            return {"status": "online", "message": "Serviço de auth disponível", "url": "https://supabase.com/dashboard/project/zawqvduiuljlvquxzlpq/auth/users"}
        return {"status": "degraded", "message": f"Status code: {response.status_code}", "url": "https://supabase.com/dashboard/project/zawqvduiuljlvquxzlpq/auth/users"}


async def check_supabase_storage() -> Dict[str, Any]:
    """Verifica se o storage do Supabase está a funcionar."""
    supabase_url = settings.SUPABASE_URL
    if not supabase_url:
        return {"status": "unknown", "message": "SUPABASE_URL não configurado"}
    
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{supabase_url}/storage/v1/bucket", timeout=5.0)
        if response.status_code in [200, 400, 401]:
            return {"status": "online", "message": "Storage disponível", "url": "https://supabase.com/dashboard/project/zawqvduiuljlvquxzlpq/storage/buckets"}
        elif response.status_code == 404:
            return {"status": "online", "message": "Storage não ativado (não utilizado)", "url": "https://supabase.com/dashboard/project/zawqvduiuljlvquxzlpq/storage/buckets"}
        return {"status": "degraded", "message": f"Status code: {response.status_code}", "url": "https://supabase.com/dashboard/project/zawqvduiuljlvquxzlpq/storage/buckets"}


async def check_supabase_table(table_name: str) -> Dict[str, Any]:
    """Verifica se uma tabela específica do Supabase está acessível."""
    supabase_url = settings.SUPABASE_URL
    supabase_key = settings.SUPABASE_ANON_KEY
    
    if not supabase_url or not supabase_key:
        return {"status": "unknown", "message": "Credenciais não configuradas"}
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{supabase_url}/rest/v1/{table_name}?limit=1",
            headers={
                "apikey": supabase_key,
                "Authorization": f"Bearer {supabase_key}"
            },
            timeout=5.0
        )
        if response.status_code == 200:
            return {"status": "online", "message": f"Tabela '{table_name}' acessível", "url": f"https://supabase.com/dashboard/project/zawqvduiuljlvquxzlpq/editor/{table_name}"}
        elif response.status_code == 401:
            return {"status": "degraded", "message": "Sem permissão (RLS ativo)", "url": f"https://supabase.com/dashboard/project/zawqvduiuljlvquxzlpq/editor/{table_name}"}
        return {"status": "offline", "message": f"Erro: {response.status_code}", "url": "https://supabase.com/dashboard/project/zawqvduiuljlvquxzlpq/editor"}


# --- HUGGING FACE (múltiplos datasets) ---

async def check_hf_dataset(repo: str) -> Dict[str, Any]:
    """Verifica acesso a um dataset específico no Hugging Face."""
    dataset_url = f"https://huggingface.co/datasets/{repo}"
    async with httpx.AsyncClient() as client:
        response = await client.head(
            dataset_url,
            timeout=5.0,
            follow_redirects=True
        )
        if response.status_code == 200:
            return {
                "status": "online",
                "message": "Dataset acessível",
                "details": {"repo": repo},
                "url": dataset_url
            }
        elif response.status_code == 404:
            return {"status": "offline", "message": "Dataset não encontrado", "url": dataset_url}
        return {"status": "degraded", "message": f"Status code: {response.status_code}", "url": dataset_url}


async def check_hf_space(repo: str) -> Dict[str, Any]:
    """Verifica o estado real de um Space no Hugging Face usando a API."""
    hf_token = settings.HF_TOKEN
    headers = {}
    if hf_token:
        headers["Authorization"] = f"Bearer {hf_token}"
    
    space_url = f"https://huggingface.co/spaces/{repo}"
    
    async with httpx.AsyncClient() as client:
        # Usar a API do HF para obter o estado real do Space
        response = await client.get(
            f"https://huggingface.co/api/spaces/{repo}",
            headers=headers,
            timeout=10.0
        )
        
        if response.status_code == 404:
            return {"status": "offline", "message": "Space não encontrado", "url": space_url}
        
        if response.status_code == 401:
            return {"status": "unknown", "message": "Space privado (sem acesso)", "details": {"repo": repo}, "url": space_url}
        
        if response.status_code != 200:
            return {"status": "degraded", "message": f"API status: {response.status_code}", "url": space_url}
        
        try:
            data = response.json()
            runtime = data.get("runtime", {})
            stage = runtime.get("stage", "unknown")
            hardware = runtime.get("hardware", {}).get("current", "unknown")
            
            # Estados possíveis do HF Space
            # RUNNING, RUNNING_BUILDING, BUILDING, PAUSED, SLEEPING, STOPPED, etc.
            
            if stage in ["RUNNING", "RUNNING_BUILDING"]:
                return {
                    "status": "online",
                    "message": f"Space a correr",
                    "details": {"repo": repo, "stage": stage, "hardware": hardware},
                    "url": space_url
                }
            elif stage == "PAUSED":
                return {
                    "status": "offline",
                    "message": "Space pausado (arquivado)",
                    "details": {"repo": repo, "stage": stage},
                    "url": space_url
                }
            elif stage == "SLEEPING":
                return {
                    "status": "degraded",
                    "message": "Space a dormir (inativo)",
                    "details": {"repo": repo, "stage": stage},
                    "url": space_url
                }
            elif stage == "BUILDING":
                return {
                    "status": "degraded",
                    "message": "Space em construção",
                    "details": {"repo": repo, "stage": stage},
                    "url": space_url
                }
            elif stage == "STOPPED":
                return {
                    "status": "offline",
                    "message": "Space parado",
                    "details": {"repo": repo, "stage": stage},
                    "url": space_url
                }
            else:
                return {
                    "status": "unknown",
                    "message": f"Estado: {stage}",
                    "details": {"repo": repo, "stage": stage},
                    "url": space_url
                }
        except Exception as e:
            return {"status": "degraded", "message": f"Erro a processar resposta: {str(e)}", "url": space_url}


# --- APIs EXTERNAS ---

async def check_google_safe_browsing() -> Dict[str, Any]:
    """Verifica se a API do Google Safe Browsing está acessível."""
    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY or settings.GOOGLE_SAFE_BROWSING_KEY
    if not api_key:
        return {"status": "unknown", "message": "API Key não configurada"}
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json={
                "client": {"clientId": "eyeweb", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": "https://google.com"}]
                }
            },
            timeout=5.0
        )
        if response.status_code == 200:
            return {"status": "online", "message": "API operacional"}
        return {"status": "degraded", "message": f"Status code: {response.status_code}"}


async def check_urlscan() -> Dict[str, Any]:
    """Verifica se a API do URLScan.io está acessível."""
    api_key = settings.URLSCAN_API_KEY
    if not api_key:
        return {"status": "unknown", "message": "API Key não configurada", "url": "https://urlscan.io/user/profile/"}
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://urlscan.io/api/v1/search/?q=domain:google.com&size=1",
            headers={"API-Key": api_key},
            timeout=5.0
        )
        if response.status_code == 200:
            return {"status": "online", "message": "API operacional", "url": "https://urlscan.io/user/profile/"}
        return {"status": "degraded", "message": f"Status code: {response.status_code}", "url": "https://urlscan.io/user/profile/"}


async def check_groq() -> Dict[str, Any]:
    """Verifica se a API do Groq está acessível."""
    api_key = settings.GROQ_API_KEY
    if not api_key:
        return {"status": "unknown", "message": "API Key não configurada", "url": "https://console.groq.com/keys"}
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.groq.com/openai/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=5.0
        )
        if response.status_code == 200:
            data = response.json()
            models = [m.get("id", "unknown") for m in data.get("data", [])[:3]]
            return {
                "status": "online", 
                "message": "API operacional",
                "details": {"modelos_disponíveis": len(data.get("data", [])), "exemplos": models},
                "url": "https://console.groq.com/keys"
            }
        return {"status": "degraded", "message": f"Status code: {response.status_code}", "url": "https://console.groq.com/keys"}


# --- INFRAESTRUTURA ---

async def check_render() -> Dict[str, Any]:
    """Verifica se o Render está a servir o backend."""
    render_url = settings.RENDER_EXTERNAL_URL
    render_dashboard = "https://dashboard.render.com/"
    if not render_url:
        if settings.ENVIRONMENT == "development":
            return {"status": "online", "message": "Ambiente local (não aplicável)", "url": render_dashboard}
        return {"status": "unknown", "message": "RENDER_EXTERNAL_URL não configurado", "url": render_dashboard}
    
    try:
        async with httpx.AsyncClient() as client:
            # Timeout maior porque o Render free tier pode estar a "acordar"
            response = await client.get(f"{render_url}/health", timeout=15.0)
            if response.status_code == 200:
                return {"status": "online", "message": "Render operacional", "url": render_dashboard}
            return {"status": "degraded", "message": f"Status code: {response.status_code}", "url": render_dashboard}
    except httpx.TimeoutException:
        return {"status": "degraded", "message": "Timeout - serviço pode estar a acordar (free tier)", "url": render_dashboard}


async def check_vercel() -> Dict[str, Any]:
    """Verifica se o frontend no Vercel está acessível."""
    vercel_url = settings.VERCEL_URL or "https://eyeweb.vercel.app"
    vercel_dashboard = "https://vercel.com/sams-projects-a500f177/eyeweb"
    
    async with httpx.AsyncClient() as client:
        response = await client.head(vercel_url, timeout=5.0, follow_redirects=True)
        if response.status_code == 200:
            return {"status": "online", "message": "Frontend operacional", "url": vercel_dashboard}
        return {"status": "degraded", "message": f"Status code: {response.status_code}", "url": vercel_dashboard}


async def check_resend() -> Dict[str, Any]:
    """Verifica conectividade com a API do Resend (serviço de email)."""
    resend_dashboard = "https://resend.com/api-keys"
    
    if not settings.RESEND_API_KEY:
        return {"status": "unknown", "message": "API Key não configurada", "url": resend_dashboard}
    
    try:
        async with httpx.AsyncClient() as client:
            # Verificar API key fazendo uma chamada simples à API
            response = await client.get(
                "https://api.resend.com/domains",
                headers={"Authorization": f"Bearer {settings.RESEND_API_KEY}"},
                timeout=5.0
            )
            
            if response.status_code == 200:
                return {"status": "online", "message": "API operacional", "url": resend_dashboard}
            elif response.status_code == 401:
                return {"status": "offline", "message": "API Key inválida", "url": resend_dashboard}
            else:
                return {"status": "degraded", "message": f"Status: {response.status_code}", "url": resend_dashboard}
    except httpx.TimeoutException:
        return {"status": "offline", "message": "Timeout na conexão", "url": resend_dashboard}
    except Exception as e:
        return {"status": "offline", "message": str(e), "url": resend_dashboard}


@router.get("/health-check", response_model=HealthCheckResponse)
async def health_check():
    """
    Verifica o estado de saúde de todos os serviços externos.
    Agora com verificações detalhadas por item.
    """
    
    # Tabelas do Supabase a verificar (apenas as que existem)
    supabase_tables = ["profiles"]
    
    # Datasets do Hugging Face
    hf_datasets = [
        "Samezinho/eye-web-breaches",
        "Samezinho/eye-web-passwords"
    ]
    
    # Spaces do Hugging Face
    hf_spaces = [
        "Samezinho/eyeweb-n8n"
    ]
    
    # Definir todos os checks por categoria
    checks = []
    
    # Backend API
    checks.append(("Backend API", check_backend_api, "Backend"))
    
    # Supabase
    checks.append(("Supabase - Conexão", check_supabase_connection, "Supabase"))
    checks.append(("Supabase - Auth", check_supabase_auth, "Supabase"))
    checks.append(("Supabase - Storage", check_supabase_storage, "Supabase"))
    for table in supabase_tables:
        checks.append((f"Tabela: {table}", lambda t=table: check_supabase_table(t), "Supabase"))
    
    # Hugging Face - Datasets
    for dataset in hf_datasets:
        short_name = dataset.split("/")[-1]
        checks.append((f"Dataset: {short_name}", lambda d=dataset: check_hf_dataset(d), "Hugging Face"))
    
    # Hugging Face - Spaces
    for space in hf_spaces:
        short_name = space.split("/")[-1]
        checks.append((f"Space: {short_name}", lambda s=space: check_hf_space(s), "Hugging Face"))
    
    # APIs Externas
    checks.append(("Google Safe Browsing", check_google_safe_browsing, "APIs Externas"))
    checks.append(("URLScan.io", check_urlscan, "APIs Externas"))
    checks.append(("Groq AI", check_groq, "APIs Externas"))
    
    # Infraestrutura
    checks.append(("Render (Backend)", check_render, "Infraestrutura"))
    checks.append(("Vercel (Frontend)", check_vercel, "Infraestrutura"))
    checks.append(("Resend (Email)", check_resend, "Infraestrutura"))
    
    # Executar todos os checks em paralelo
    tasks = [check_service(name, func, cat) for name, func, cat in checks]
    services = await asyncio.gather(*tasks)
    
    # Calcular resumo
    summary = {"online": 0, "offline": 0, "degraded": 0, "unknown": 0}
    for service in services:
        summary[service.status] = summary.get(service.status, 0) + 1
    
    # Agrupar por categoria
    categories: Dict[str, List[ServiceStatus]] = {}
    for service in services:
        cat = service.category or "Outros"
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(service)
    
    # Determinar status geral
    if summary["offline"] > 0:
        overall_status = "critical"
    elif summary["degraded"] > 0:
        overall_status = "degraded"
    elif summary["unknown"] > len(services) // 2:
        overall_status = "unknown"
    else:
        overall_status = "healthy"
    
    return HealthCheckResponse(
        overall_status=overall_status,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        services=services,
        summary=summary,
        categories=categories
    )
