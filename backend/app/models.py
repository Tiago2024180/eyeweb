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
    
    NOVA ESTRUTURA v2.0:
    - Campos booleanos individuais para cada tipo de dado exposto
    - Campo 'type' para distinguir email de phone
    """
    
    hash: str = Field(
        ...,
        description="Hash SHA-256 completo do email/telefone comprometido"
    )
    
    type: str = Field(
        ...,
        description="Tipo de dado: 'email' ou 'phone'"
    )
    
    breach_name: str = Field(
        ...,
        description="Nome do breach/leak onde o dado foi encontrado"
    )
    
    breach_date: str = Field(
        ...,
        description="Data do breach (formato: YYYY-MM-DD)"
    )
    
    # Campos booleanos para cada tipo de dado exposto
    has_password: bool = Field(
        default=False,
        description="Password foi exposta neste breach?"
    )
    
    has_ip: bool = Field(
        default=False,
        description="Endereço IP foi exposto neste breach?"
    )
    
    has_username: bool = Field(
        default=False,
        description="Username foi exposto neste breach?"
    )
    
    has_credit_card: bool = Field(
        default=False,
        description="Dados de cartão de crédito foram expostos neste breach?"
    )
    
    has_history: bool = Field(
        default=False,
        description="Histórico de atividade foi exposto neste breach?"
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
    
    NOVA ESTRUTURA v2.0:
    - Separação de contagem por tipo (emails vs telefones)
    """
    
    total_records: int = Field(
        ...,
        description="Número total de registos no dataset"
    )
    
    total_emails: int = Field(
        default=0,
        description="Número de registos de email"
    )
    
    total_phones: int = Field(
        default=0,
        description="Número de registos de telefone"
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
