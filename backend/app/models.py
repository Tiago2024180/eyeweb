"""
===========================================
Eye Web Backend — Modelos Pydantic
===========================================
Define os schemas de request/response da API.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


# ===========================================
# MODELOS DE REQUEST
# ===========================================

class BreachCheckRequest(BaseModel):
    """
    Request para verificar se um hash está em algum breach.
    
    O cliente envia apenas o PREFIXO do hash SHA-256.
    O email original nunca é enviado!
    """
    
    prefix: str = Field(
        ...,
        min_length=2,
        max_length=6,
        pattern="^[0-9a-f]+$",
        description="Prefixo do hash SHA-256 (2-6 caracteres hexadecimais)",
        examples=["ef72", "a3b1c2"]
    )


# ===========================================
# MODELOS DE RESPONSE
# ===========================================

class BreachInfo(BaseModel):
    """
    Informações sobre um breach individual.
    """
    
    hash: str = Field(
        ...,
        description="Hash SHA-256 completo do email comprometido"
    )
    
    breach_name: str = Field(
        ...,
        description="Nome do breach/leak onde o email foi encontrado"
    )
    
    breach_date: str = Field(
        ...,
        description="Data do breach (formato: YYYY-MM-DD)"
    )
    
    data_classes: List[str] = Field(
        ...,
        description="Tipos de dados expostos (ex: email, password, phone)"
    )


class BreachCheckResponse(BaseModel):
    """
    Response com todos os hashes candidatos que correspondem ao prefixo.
    
    O cliente deve comparar localmente se o hash completo do seu email
    está presente na lista de candidatos.
    """
    
    prefix: str = Field(
        ...,
        description="Prefixo pesquisado"
    )
    
    count: int = Field(
        ...,
        description="Número de hashes encontrados com este prefixo"
    )
    
    candidates: List[BreachInfo] = Field(
        ...,
        description="Lista de breaches candidatos"
    )


class HealthResponse(BaseModel):
    """
    Response do endpoint de health check.
    """
    
    status: str = Field(
        default="healthy",
        description="Estado da API"
    )
    
    version: str = Field(
        ...,
        description="Versão da API"
    )
    
    dataset_repo: str = Field(
        ...,
        description="Repositório do dataset no Hugging Face"
    )


class StatsResponse(BaseModel):
    """
    Response com estatísticas do dataset.
    """
    
    total_records: int = Field(
        ...,
        description="Número total de registos no dataset"
    )
    
    total_partitions: int = Field(
        ...,
        description="Número de partições"
    )
    
    prefix_length: int = Field(
        ...,
        description="Comprimento do prefixo usado nas partições"
    )
    
    last_updated: Optional[str] = Field(
        None,
        description="Data da última atualização do dataset"
    )


class ErrorResponse(BaseModel):
    """
    Response padrão para erros.
    """
    
    error: str = Field(
        ...,
        description="Mensagem de erro"
    )
    
    detail: Optional[str] = Field(
        None,
        description="Detalhes adicionais do erro"
    )
