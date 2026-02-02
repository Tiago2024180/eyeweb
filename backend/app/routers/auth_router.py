"""
===========================================
Eye Web Backend — Auth Router
===========================================
Endpoints para verificação de login com código.
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr
from typing import List, Optional

from ..services.auth_service import (
    generate_verification_codes,
    generate_session_id,
    store_verification_code,
    verify_code,
    send_verification_email
)
from ..config import get_settings

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


# ===========================================
# MODELOS
# ===========================================

class SendCodeRequest(BaseModel):
    email: EmailStr


class SendCodeResponse(BaseModel):
    success: bool
    codes: List[str]
    session_id: str
    expires_in: int  # segundos
    message: str
    dev_hint: Optional[str] = None  # Apenas para dev quando email não é enviado


class VerifyCodeRequest(BaseModel):
    session_id: str
    code: str
    email: EmailStr


class VerifyCodeResponse(BaseModel):
    success: bool
    message: str


# ===========================================
# ENDPOINTS
# ===========================================

@router.post("/send-code", response_model=SendCodeResponse)
async def send_verification_code(request: SendCodeRequest):
    """
    Gera e envia código de verificação para o email.
    
    Retorna 3 códigos, sendo 1 o correto (enviado por email).
    O utilizador deve clicar no código correto para completar o login.
    """
    email = request.email.lower().strip()
    
    # Gerar códigos
    codes, correct_code = generate_verification_codes()
    session_id = generate_session_id()
    
    # Armazenar no Supabase
    stored = await store_verification_code(email, session_id, correct_code)
    
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao gerar código de verificação. Tenta novamente."
        )
    
    # Enviar email com Resend
    email_sent = await send_verification_email(email, correct_code)
    
    # Se o email não foi enviado, incluir dica para desenvolvimento
    dev_hint = None
    if not email_sent:
        if settings.DEBUG or settings.ENVIRONMENT == "development":
            dev_hint = f"[DEV] O código correto é: {correct_code}"
        else:
            # Em produção, ainda retornamos os códigos mas avisamos
            dev_hint = "Email não enviado - verifique configuração Resend"
    
    return SendCodeResponse(
        success=True,
        codes=codes,
        session_id=session_id,
        expires_in=300,  # 5 minutos
        message="Código enviado para o teu email!" if email_sent else "Código gerado (email não configurado)",
        dev_hint=dev_hint
    )


@router.post("/verify-code", response_model=VerifyCodeResponse)
async def verify_verification_code(request: VerifyCodeRequest):
    """
    Verifica se o código submetido está correto.
    
    Se correto, o frontend pode prosseguir com o login real no Supabase.
    """
    success, message = await verify_code(request.session_id, request.code)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    return VerifyCodeResponse(
        success=True,
        message=message
    )
