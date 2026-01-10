"""
===========================================
Eye Web Backend — Breach Router
===========================================
Endpoints para verificação de breaches.
"""

import logging
from typing import List

from fastapi import APIRouter, HTTPException, Query, Depends

from ..models import (
    BreachCheckRequest,
    BreachCheckResponse,
    BreachInfo,
    StatsResponse,
    ErrorResponse
)
from ..services.breach_service import get_breach_service, BreachService

# Configurar logging
logger = logging.getLogger(__name__)

# Criar router
router = APIRouter(
    prefix="/breaches",
    tags=["Breaches"],
    responses={
        404: {"model": ErrorResponse, "description": "Recurso não encontrado"},
        500: {"model": ErrorResponse, "description": "Erro interno do servidor"}
    }
)


# ===========================================
# DEPENDENCY INJECTION
# ===========================================

async def get_service() -> BreachService:
    """Dependency para injetar o BreachService."""
    return get_breach_service()


# ===========================================
# ENDPOINTS
# ===========================================

@router.get(
    "/check/{prefix}",
    response_model=BreachCheckResponse,
    summary="Verificar breaches por prefixo",
    description="""
    Verifica se existem breaches para um determinado prefixo de hash.
    
    ## Como usar
    
    1. No cliente (browser), gera o hash SHA-256 do email normalizado
    2. Extrai os primeiros 2-6 caracteres do hash (prefixo)
    3. Envia o prefixo para este endpoint
    4. Recebe lista de hashes candidatos
    5. Compara localmente se o hash completo está na lista
    
    ## Exemplo
    
    ```javascript
    // No browser
    const email = "user@example.com";
    const hash = await sha256(email.toLowerCase().trim());
    const prefix = hash.substring(0, 5);  // ex: "ef724"
    
    // Request à API
    const response = await fetch(`/api/v1/breaches/check/${prefix}`);
    const data = await response.json();
    
    // Verificar localmente
    const isBreached = data.candidates.some(c => c.hash === hash);
    ```
    
    ## Privacidade
    
    - O email NUNCA é enviado
    - O servidor NUNCA conhece o hash completo
    - Modelo K-Anonymity garante privacidade
    """,
    responses={
        200: {
            "description": "Lista de breaches candidatos",
            "content": {
                "application/json": {
                    "example": {
                        "prefix": "ef724",
                        "count": 3,
                        "candidates": [
                            {
                                "hash": "ef724abc123...",
                                "breach_name": "LinkedIn2021",
                                "breach_date": "2021-06-22",
                                "data_classes": ["email", "password"]
                            }
                        ]
                    }
                }
            }
        }
    }
)
async def check_breaches(
    prefix: str,
    service: BreachService = Depends(get_service)
) -> BreachCheckResponse:
    """
    Endpoint principal para verificação de breaches.
    
    Args:
        prefix: Prefixo do hash SHA-256 (2-6 caracteres hexadecimais)
        
    Returns:
        Lista de breaches candidatos que correspondem ao prefixo
    """
    # Validar prefixo
    prefix = prefix.lower().strip()
    
    if len(prefix) < 2:
        raise HTTPException(
            status_code=400,
            detail="Prefixo deve ter pelo menos 2 caracteres"
        )
    
    if len(prefix) > 6:
        raise HTTPException(
            status_code=400,
            detail="Prefixo não pode ter mais de 6 caracteres"
        )
    
    # Validar se é hexadecimal
    try:
        int(prefix, 16)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Prefixo deve conter apenas caracteres hexadecimais (0-9, a-f)"
        )
    
    try:
        # Consultar serviço
        results = await service.check_breaches(prefix)
        
        # Converter para modelo de resposta
        candidates = [
            BreachInfo(
                hash=r["hash"],
                breach_name=r["breach_name"],
                breach_date=r["breach_date"],
                data_classes=r["data_classes"]
            )
            for r in results
        ]
        
        return BreachCheckResponse(
            prefix=prefix,
            count=len(candidates),
            candidates=candidates
        )
        
    except Exception as e:
        logger.error(f"Erro ao verificar breaches: {e}")
        raise HTTPException(
            status_code=500,
            detail="Erro interno ao processar pedido"
        )


@router.post(
    "/check",
    response_model=BreachCheckResponse,
    summary="Verificar breaches (POST)",
    description="Alternativa POST ao endpoint GET. Útil para clientes que preferem enviar dados no body."
)
async def check_breaches_post(
    request: BreachCheckRequest,
    service: BreachService = Depends(get_service)
) -> BreachCheckResponse:
    """
    Endpoint POST alternativo para verificação de breaches.
    
    Útil quando o cliente prefere enviar o prefixo no body
    em vez de na URL.
    """
    return await check_breaches(request.prefix, service)


@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Estatísticas do dataset",
    description="Retorna informações sobre o dataset de breaches."
)
async def get_stats(
    service: BreachService = Depends(get_service)
) -> StatsResponse:
    """
    Retorna estatísticas do dataset.
    
    Returns:
        Informações sobre tamanho, partições e última atualização
    """
    try:
        metadata = await service.get_metadata()
        
        if metadata is None:
            # Retornar valores padrão se não houver metadados
            return StatsResponse(
                total_records=0,
                total_partitions=256,
                prefix_length=2,
                last_updated=None
            )
        
        return StatsResponse(
            total_records=metadata.get("total_records", 0),
            total_partitions=metadata.get("total_partitions", 256),
            prefix_length=metadata.get("prefix_length", 2),
            last_updated=metadata.get("generated_at")
        )
        
    except Exception as e:
        logger.error(f"Erro ao obter estatísticas: {e}")
        raise HTTPException(
            status_code=500,
            detail="Erro ao obter estatísticas do dataset"
        )


@router.get(
    "/cache-stats",
    summary="Estatísticas do cache",
    description="Retorna informações sobre o estado do cache (apenas para debug)."
)
async def get_cache_stats(
    service: BreachService = Depends(get_service)
) -> dict:
    """
    Retorna estatísticas do cache interno.
    
    Útil para monitorização e debug.
    """
    return service.get_cache_stats()
