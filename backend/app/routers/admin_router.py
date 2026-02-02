"""
===========================================
Eye Web Backend — Admin MFA Router
===========================================
Endpoints para verificação MFA do administrador.
Usa TOTP com HMAC-SHA256 sincronizado com o programa local.
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr
from typing import Optional
import time
import hashlib
import hmac
import struct
import os

from ..config import get_settings

router = APIRouter(prefix="/admin", tags=["admin"])
settings = get_settings()


# ===========================================
# CONFIGURAÇÃO TOTP
# ===========================================

# Secret partilhado com o programa local (eyeweb_auth.py)
# DEVE SER IGUAL em ambos os lados!
TOTP_SECRET = os.getenv("ADMIN_MFA_SECRET", "EyeWeb_Admin_MFA_Secret_2026_#_01_Secure_#")

# Configuração TOTP
TOTP_INTERVAL = 30  # segundos
TOTP_DIGITS = 6     # dígitos (igual ao Supabase OTP)
TOTP_WINDOW = 4     # Aceitar códigos dos últimos 4 intervalos (2 minutos)

# Admin email hash (verificação extra)
ADMIN_EMAIL_HASH = os.getenv("ADMIN_EMAIL_HASH", "638b688642a18a2fdfdcc32195837e43074542b07d86b24fa5ecdc8e24bf3776")


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
