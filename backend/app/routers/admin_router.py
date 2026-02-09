"""
===========================================
Eye Web Backend — Admin MFA Router
===========================================
Endpoints para verificação MFA do administrador.
Usa TOTP com HMAC-SHA256 sincronizado com o programa local.
Cada admin tem o seu próprio secret MFA guardado na DB.
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
from supabase import create_client, Client

# Carregar .env automaticamente
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)

from ..config import get_settings

router = APIRouter(prefix="/admin", tags=["admin"])
settings = get_settings()


# ===========================================
# SUPABASE CLIENT
# ===========================================

def get_supabase() -> Client:
    """Retorna cliente Supabase configurado."""
    url = os.getenv("SUPABASE_URL", "")
    key = os.getenv("SUPABASE_SERVICE_KEY", "")
    if not url or not key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Supabase não configurado."
        )
    return create_client(url, key)


# ===========================================
# CONFIGURAÇÃO TOTP
# ===========================================

# Configuração TOTP (igual para todos os admins)
TOTP_INTERVAL = 30  # segundos
TOTP_DIGITS = 6     # dígitos
TOTP_WINDOW = 4     # Aceitar códigos dos últimos 4 intervalos (2 minutos)

# Fallback secret global (apenas se admin não tiver secret na DB)
FALLBACK_TOTP_SECRET = os.getenv("ADMIN_MFA_SECRET", "")


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

def generate_totp(secret: str, digits: int = 6, interval: int = 30, offset: int = 0) -> str:
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


def verify_totp(code: str, secret: str, window: int = TOTP_WINDOW) -> bool:
    """
    Verifica se o código TOTP é válido.
    
    Aceita códigos do período atual e dos períodos adjacentes (window).
    
    Args:
        code: Código a verificar
        secret: Secret do admin específico
        window: Número de períodos adjacentes a aceitar
    
    Returns:
        True se o código é válido
    """
    if not secret:
        return False
    
    # Verificar código atual e adjacentes (para compensar dessincronização)
    for offset in range(-window, window + 1):
        expected_code = generate_totp(secret, TOTP_DIGITS, TOTP_INTERVAL, offset)
        if code == expected_code:
            return True
    
    return False


async def get_admin_from_db(email: str) -> Optional[Dict[str, Any]]:
    """
    Busca um admin na tabela profiles pelo email.
    
    Returns:
        Dict com dados do admin ou None se não encontrado/não é admin
    """
    try:
        supabase = get_supabase()
        result = supabase.table("profiles").select("*").eq("email", email.lower().strip()).eq("role", "admin").execute()
        
        if result.data and len(result.data) > 0:
            return result.data[0]
        return None
    except Exception as e:
        print(f"❌ Erro ao buscar admin: {e}")
        return None


async def get_admin_mfa_secret(admin_id: str) -> Optional[str]:
    """
    Busca o secret MFA de um admin específico na tabela admin_mfa_secrets.
    
    Args:
        admin_id: UUID do admin (da tabela profiles)
    
    Returns:
        Secret MFA ou None se não configurado
    """
    try:
        supabase = get_supabase()
        result = supabase.table("admin_mfa_secrets").select("secret_key").eq("admin_id", admin_id).eq("is_configured", True).execute()
        
        if result.data and len(result.data) > 0:
            return result.data[0].get("secret_key")
        return None
    except Exception as e:
        print(f"❌ Erro ao buscar MFA secret: {e}")
        return None


def is_admin_email(email: str) -> bool:
    """
    Verifica se o email é de um admin via consulta à DB.
    DEPRECATED: Usar get_admin_from_db() para verificação completa.
    """
    # Mantido para compatibilidade, mas agora verifica na DB
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Se já há um loop, criar task
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(lambda: asyncio.run(get_admin_from_db(email)))
                admin = future.result()
        else:
            admin = asyncio.run(get_admin_from_db(email))
        return admin is not None
    except Exception as e:
        print(f"❌ Erro em is_admin_email: {e}")
        return False


# ===========================================
# ENDPOINTS
# ===========================================

@router.post("/verify-mfa", response_model=VerifyMFAResponse)
async def verify_admin_mfa(request: VerifyMFARequest):
    """
    Verifica o código MFA do administrador.
    
    O código é gerado pelo programa local (eyeweb_auth.py) usando TOTP.
    Cada admin tem o seu próprio secret MFA guardado na DB.
    
    - Código de 6 dígitos
    - Válido por 30 segundos
    - Aceita 4 períodos de margem (2 minutos)
    """
    email = request.email.lower().strip()
    code = request.code.strip()
    
    # 1. Verificar se é admin na DB (role='admin')
    admin = await get_admin_from_db(email)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este email não tem permissões de administrador."
        )
    
    admin_id = admin.get("id")
    admin_name = admin.get("display_name", email)
    
    print(f"🔐 MFA Verify - Admin: {admin_name} ({email})")
    
    # 2. Validar formato do código
    if len(code) != TOTP_DIGITS or not code.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"O código deve ter {TOTP_DIGITS} dígitos numéricos."
        )
    
    # 3. Buscar secret MFA individual do admin
    admin_secret = await get_admin_mfa_secret(admin_id)
    
    print(f"🔑 Secret da DB: {admin_secret[:10] if admin_secret else 'None'}...")
    
    # Se não tem secret individual, usar fallback global
    if not admin_secret:
        print(f"⚠️  Admin {admin_name} não tem secret MFA configurado. Usando fallback global.")
        admin_secret = FALLBACK_TOTP_SECRET
        print(f"🔑 Fallback secret: {admin_secret[:10] if admin_secret else 'None'}...")
    
    if not admin_secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA não configurado para este administrador. Contacte o suporte."
        )
    
    # 4. Verificar código TOTP
    print(f"🔢 Código recebido: {code}")
    expected = generate_totp(admin_secret, TOTP_DIGITS, TOTP_INTERVAL, 0)
    print(f"🔢 Código esperado (offset 0): {expected}")
    
    if not verify_totp(code, admin_secret, TOTP_WINDOW):
        # TODO: Registar tentativa falhada na tabela mfa_attempts
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Código MFA inválido ou expirado."
        )
    
    # 5. Código válido!
    print(f"✅ MFA verificado com sucesso para {admin_name}")
    return VerifyMFAResponse(
        success=True,
        message="Código MFA verificado com sucesso!"
    )


@router.get("/test-totp")
async def test_totp():
    """
    Endpoint de teste para verificar geração TOTP (apenas em desenvolvimento).
    
    Retorna o código TOTP atual usando o fallback secret.
    """
    if not settings.DEBUG and settings.ENVIRONMENT != "development":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este endpoint só está disponível em desenvolvimento."
        )
    
    current_code = generate_totp(FALLBACK_TOTP_SECRET, TOTP_DIGITS, TOTP_INTERVAL)
    time_remaining = TOTP_INTERVAL - (int(time.time()) % TOTP_INTERVAL)
    
    return {
        "current_code": current_code,
        "time_remaining": time_remaining,
        "interval": TOTP_INTERVAL,
        "digits": TOTP_DIGITS,
        "note": "Este código usa o fallback secret global. Cada admin deve ter o seu próprio secret."
    }


# ===========================================
# GESTOR DE E-MAILS
# ===========================================

class SendBroadcastEmailRequest(BaseModel):
    """Request para enviar email em massa."""
    subject: str
    message: str  # Conteúdo HTML ou texto
    test_mode: bool = False  # Se True, envia apenas para o admin


class SendBroadcastEmailResponse(BaseModel):
    """Response do envio de email em massa."""
    success: bool
    message: str
    total_recipients: int
    successful_sends: int
    failed_sends: int
    failed_emails: Optional[List[str]] = None


class EmailSubscriber(BaseModel):
    """Modelo de subscritor."""
    email: str
    display_name: Optional[str] = None
    subscribed_at: Optional[str] = None


class EmailStatsResponse(BaseModel):
    """Estatísticas de email."""
    total_subscribers: int
    subscribers: List[EmailSubscriber]


def get_broadcast_email_template(subject: str, message: str) -> str:
    """
    Template HTML para emails de broadcast/comunicados.
    """
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{subject}</title>
    </head>
    <body style="margin: 0; padding: 0; background-color: #0a0a0a; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #0a0a0a; padding: 40px 20px;">
            <tr>
                <td align="center">
                    <table width="100%" max-width="600" cellpadding="0" cellspacing="0" style="background-color: #111111; border-radius: 16px; border: 1px solid #222222; overflow: hidden;">
                        <!-- Header -->
                        <tr>
                            <td style="padding: 32px 32px 24px; text-align: center; border-bottom: 1px solid #222222;">
                                <h1 style="margin: 0; font-size: 24px; font-weight: 700; color: #ffffff;">Eye Web</h1>
                                <p style="margin: 8px 0 0; font-size: 14px; color: #666666;">Site Oficial do EyeWeb</p>
                            </td>
                        </tr>
                        
                        <!-- Content -->
                        <tr>
                            <td style="padding: 32px;">
                                <h2 style="margin: 0 0 20px; font-size: 22px; font-weight: 600; color: #ffffff;">
                                    {subject}
                                </h2>
                                
                                <div style="font-size: 15px; color: #cccccc; line-height: 1.7;">
                                    {message}
                                </div>
                            </td>
                        </tr>
                        
                        <!-- Footer -->
                        <tr>
                            <td style="padding: 24px 32px; background-color: #0a0a0a; border-top: 1px solid #222222;">
                                <p style="margin: 0 0 8px; font-size: 13px; color: #666666; text-align: center;">
                                    EyeWeb: Let's keep an eye on each other.
                                </p>
                                <p style="margin: 0; font-size: 12px; text-align: center;">
                                    <a href="https://eyeweb.vercel.app" style="color: #ff0000; text-decoration: none;">Link para o Eye Web</a>
                                </p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """


def get_welcome_email_template(display_name: str) -> str:
    """
    Template HTML para email de boas-vindas.
    """
    name = display_name or "Utilizador"
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Bem-vindo ao Eye Web!</title>
    </head>
    <body style="margin: 0; padding: 0; background-color: #0a0a0a; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #0a0a0a; padding: 40px 20px;">
            <tr>
                <td align="center">
                    <table width="100%" max-width="600" cellpadding="0" cellspacing="0" style="background-color: #111111; border-radius: 16px; border: 1px solid #222222; overflow: hidden;">
                        <!-- Header -->
                        <tr>
                            <td style="padding: 32px 32px 24px; text-align: center; border-bottom: 1px solid #222222;">
                                <div style="font-size: 48px; margin-bottom: 16px;">🎉</div>
                                <h1 style="margin: 0; font-size: 28px; font-weight: 700; color: #3b82f6;">Bem-vindo ao Eye Web!</h1>
                            </td>
                        </tr>
                        
                        <!-- Content -->
                        <tr>
                            <td style="padding: 32px;">
                                <p style="margin: 0 0 20px; font-size: 18px; color: #ffffff;">
                                    Olá <strong>{name}</strong>! 👋
                                </p>
                                
                                <p style="margin: 0 0 20px; font-size: 15px; color: #cccccc; line-height: 1.7;">
                                    Obrigado por te registares no <strong style="color: #3b82f6;">Eye Web</strong>! 
                                    A tua segurança online é a nossa prioridade.
                                </p>
                                
                                <div style="background-color: #1a1a2e; border-radius: 12px; padding: 20px; margin-bottom: 20px;">
                                    <h3 style="margin: 0 0 12px; font-size: 16px; color: #3b82f6;">O que podes fazer:</h3>
                                    <ul style="margin: 0; padding: 0 0 0 20px; color: #cccccc; line-height: 1.8;">
                                        <li>🔍 <strong>Verificar emails</strong> — Descobre se os teus dados foram expostos</li>
                                        <li>🔐 <strong>Testar passwords</strong> — Verifica se são seguras</li>
                                        <li>🌐 <strong>Analisar URLs</strong> — Detecta sites maliciosos</li>
                                        <li>📱 <strong>Verificar telefones</strong> — Confirma a segurança do teu número</li>
                                    </ul>
                                </div>
                                
                                <p style="margin: 0 0 20px; font-size: 15px; color: #888888; line-height: 1.7;">
                                    Todos os dados são verificados usando <strong style="color: #22c55e;">K-Anonymity</strong> — 
                                    nunca enviamos as tuas informações completas, apenas prefixos de hash.
                                </p>
                                
                                <div style="text-align: center; margin-top: 24px;">
                                    <a href="https://eyeweb.vercel.app" style="display: inline-block; background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 16px;">
                                        Começar a usar o Eye Web
                                    </a>
                                </div>
                            </td>
                        </tr>
                        
                        <!-- Footer -->
                        <tr>
                            <td style="padding: 24px 32px; background-color: #0a0a0a; border-top: 1px solid #222222;">
                                <p style="margin: 0 0 8px; font-size: 13px; color: #666666; text-align: center;">
                                    EyeWeb: Let's keep an eye on each other.
                                </p>
                                <p style="margin: 0; font-size: 12px; text-align: center;">
                                    <a href="https://eyeweb.vercel.app" style="color: #ff0000; text-decoration: none;">Link para o Eye Web</a>
                                </p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """


# Brevo API Key - carregar de variável de ambiente
BREVO_API_KEY = os.getenv("BREVO_API_KEY", "")


async def send_email_via_brevo(to_email: str, subject: str, html_content: str) -> bool:
    """
    Envia um email usando a API do Brevo.
    
    Returns:
        True se enviado com sucesso, False caso contrário
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.brevo.com/v3/smtp/email",
                headers={
                    "api-key": BREVO_API_KEY,
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                json={
                    "sender": {
                        "name": "Eye Web",
                        "email": "eyeweb.app@gmail.com"
                    },
                    "to": [{"email": to_email}],
                    "subject": subject,
                    "htmlContent": html_content
                },
                timeout=15.0
            )
            print(f"Brevo response for {to_email}: {response.status_code} - {response.text}")
            return response.status_code in [200, 201]
    except Exception as e:
        print(f"Erro ao enviar email para {to_email}: {e}")
        return False


@router.get("/emails/subscribers", response_model=EmailStatsResponse)
async def get_email_subscribers():
    """
    Obtém a lista de subscritores (utilizadores registados).
    """
    if not settings.SUPABASE_URL or not settings.SUPABASE_SERVICE_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Supabase não configurado"
        )
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{settings.SUPABASE_URL}/rest/v1/profiles",
                headers={
                    "apikey": settings.SUPABASE_SERVICE_KEY,
                    "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
                    "Content-Type": "application/json"
                },
                params={
                    "select": "email,display_name,created_at",
                    "order": "created_at.desc"
                },
                timeout=10.0
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Erro ao obter subscritores"
                )
            
            data = response.json()
            subscribers = [
                EmailSubscriber(
                    email=row.get("email", ""),
                    display_name=row.get("display_name"),
                    subscribed_at=row.get("created_at")
                )
                for row in data
                if row.get("email")  # Filtrar registos sem email
            ]
            
            return EmailStatsResponse(
                total_subscribers=len(subscribers),
                subscribers=subscribers
            )
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro: {str(e)}"
        )


@router.post("/emails/broadcast", response_model=SendBroadcastEmailResponse)
async def send_broadcast_email(request: SendBroadcastEmailRequest):
    """
    Envia um email em massa para todos os subscritores.
    
    - test_mode=True: envia apenas para o admin
    - test_mode=False: envia para todos os utilizadores
    """
    # Validar conteúdo
    if not request.subject.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O assunto não pode estar vazio"
        )
    
    if not request.message.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A mensagem não pode estar vazia"
        )
    
    # Obter lista de emails
    if request.test_mode:
        # Modo teste: apenas admin
        recipients = ["sam.oliveira.dev@gmail.com"]
    else:
        # Modo real: todos os subscritores
        stats = await get_email_subscribers()
        recipients = [sub.email for sub in stats.subscribers if sub.email]
    
    if not recipients:
        return SendBroadcastEmailResponse(
            success=False,
            message="Nenhum destinatário encontrado",
            total_recipients=0,
            successful_sends=0,
            failed_sends=0
        )
    
    # Criar template HTML
    html_content = get_broadcast_email_template(request.subject, request.message)
    
    # Enviar emails
    successful = 0
    failed = 0
    failed_emails = []
    
    for email in recipients:
        success = await send_email_via_brevo(email, request.subject, html_content)
        if success:
            successful += 1
        else:
            failed += 1
            failed_emails.append(email)
        
        # Pequeno delay para não sobrecarregar a API
        await asyncio.sleep(0.1)
    
    return SendBroadcastEmailResponse(
        success=failed == 0,
        message=f"Emails enviados: {successful}/{len(recipients)}" if successful > 0 else "Falha ao enviar emails",
        total_recipients=len(recipients),
        successful_sends=successful,
        failed_sends=failed,
        failed_emails=failed_emails if failed > 0 else None
    )


@router.post("/emails/welcome")
async def send_welcome_email(email: str, display_name: Optional[str] = None):
    """
    Envia email de boas-vindas para um novo utilizador.
    
    Este endpoint pode ser chamado automaticamente após registo.
    """
    html_content = get_welcome_email_template(display_name or "")
    success = await send_email_via_brevo(
        email,
        "🎉 Bem-vindo ao Eye Web!",
        html_content
    )
    
    if success:
        return {"success": True, "message": "Email de boas-vindas enviado!"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha ao enviar email de boas-vindas"
        )


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


async def check_brevo() -> Dict[str, Any]:
    """Verifica conectividade com a API do Brevo (serviço de email)."""
    brevo_dashboard = "https://app.brevo.com/settings/keys/api"
    
    if not BREVO_API_KEY:
        return {"status": "unknown", "message": "API Key não configurada", "url": brevo_dashboard}
    
    try:
        async with httpx.AsyncClient() as client:
            # Verificar conta do Brevo
            response = await client.get(
                "https://api.brevo.com/v3/account",
                headers={
                    "api-key": BREVO_API_KEY,
                    "Accept": "application/json"
                },
                timeout=5.0
            )
            
            if response.status_code == 401:
                return {"status": "offline", "message": "API Key inválida", "url": brevo_dashboard}
            elif response.status_code == 200:
                data = response.json()
                plan = data.get("plan", [{}])[0].get("type", "unknown") if data.get("plan") else "unknown"
                return {
                    "status": "online", 
                    "message": "API operacional",
                    "details": {"plano": plan},
                    "url": brevo_dashboard
                }
            else:
                return {"status": "degraded", "message": f"Status: {response.status_code}", "url": brevo_dashboard}
    except httpx.TimeoutException:
        return {"status": "offline", "message": "Timeout na conexão", "url": brevo_dashboard}
    except Exception as e:
        return {"status": "offline", "message": str(e), "url": brevo_dashboard}


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
    checks.append(("Brevo (Email)", check_brevo, "Infraestrutura"))
    
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
