"""
===========================================
Eye Web Backend — Password Router
===========================================

Endpoints para verificação de passwords em fugas de dados.
Usa K-Anonymity para proteger a privacidade do utilizador.

A password NUNCA é enviada para o servidor!
Apenas os primeiros 5 caracteres do hash SHA-256 são recebidos.
"""

import logging
from fastapi import APIRouter, HTTPException

from ..services.password_service import get_password_service

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/passwords",
    tags=["Passwords"],
)


@router.get("/check/{prefix}")
async def check_password_prefix(prefix: str):
    """
    Verifica passwords com base no prefixo do hash (K-Anonymity).
    
    Este endpoint implementa K-Anonymity:
    - O cliente calcula o hash SHA-256 da password localmente
    - Envia apenas os primeiros 5 caracteres do hash
    - O servidor retorna todas as passwords com esse prefixo
    - O cliente verifica localmente se a sua password está na lista
    
    Args:
        prefix: Primeiros 5 caracteres do hash SHA-256 (hexadecimal)
        
    Returns:
        Lista de hashes de passwords que correspondem ao prefixo
    """
    # Validar o prefixo
    if not prefix or len(prefix) < 2:
        raise HTTPException(
            status_code=400,
            detail="Prefixo inválido. Deve ter pelo menos 2 caracteres hexadecimais."
        )
    
    # Normalizar para minúsculas
    prefix = prefix.lower()
    
    # Validar se é hexadecimal
    try:
        int(prefix, 16)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Prefixo inválido. Deve ser hexadecimal (0-9, a-f)."
        )
    
    logger.debug(f"🔍 A verificar passwords com prefixo: {prefix}")
    
    # Obter o serviço de passwords
    service = get_password_service()
    
    # Verificar se o dataset existe
    if not service.dataset_exists():
        logger.info("ℹ️ Dataset de passwords ainda não configurado")
        return {
            "prefix": prefix,
            "count": 0,
            "candidates": [],
            "message": "Dataset de passwords ainda não configurado."
        }
    
    # Buscar passwords com este prefixo
    candidates = await service.get_passwords_by_prefix(prefix)
    
    return {
        "prefix": prefix,
        "count": len(candidates),
        "candidates": candidates,
    }


@router.get("/stats")
async def get_password_stats():
    """
    Retorna estatísticas do dataset de passwords.
    """
    service = get_password_service()
    
    if not service.dataset_exists():
        return {
            "configured": False,
            "total_passwords": 0,
            "message": "Dataset de passwords ainda não configurado."
        }
    
    stats = await service.get_stats()
    return {
        "configured": True,
        **stats
    }
