"""
===========================================
Eye Web Backend — Breach Service
===========================================
Serviço responsável por consultar o dataset de breaches.

OTIMIZADO para o Render Free Tier (512MB RAM):
- Leitura seletiva de ficheiros Parquet remotos
- Cache LRU com TTL para reduzir chamadas HTTP
- Não carrega o dataset inteiro em memória
"""

import json
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta

import httpx
import pandas as pd
from io import BytesIO
from cachetools import TTLCache

from ..config import get_settings

# Configurar logging
logger = logging.getLogger(__name__)
settings = get_settings()


class BreachService:
    """
    Serviço para consultar breaches no dataset do Hugging Face.
    
    Características:
    - Leitura lazy de partições (só carrega quando necessário)
    - Cache em memória com TTL
    - Leitura direta de ficheiros Parquet remotos
    """
    
    def __init__(self):
        """Inicializa o serviço com cache configurado."""
        
        # Cache TTL: guarda partições em memória por X segundos
        # Chave: prefixo, Valor: DataFrame da partição
        self._cache: TTLCache = TTLCache(
            maxsize=settings.CACHE_MAX_SIZE,
            ttl=settings.CACHE_TTL_SECONDS
        )
        
        # Cache para metadados do dataset
        self._metadata_cache: Optional[Dict] = None
        self._metadata_timestamp: Optional[datetime] = None
        
        # Cliente HTTP reutilizável
        self._http_client: Optional[httpx.AsyncClient] = None
        
        logger.info(f"BreachService inicializado")
        logger.info(f"  Dataset: {settings.HF_DATASET_REPO}")
        logger.info(f"  Cache: {settings.CACHE_MAX_SIZE} partições, TTL={settings.CACHE_TTL_SECONDS}s")
    
    async def _get_http_client(self) -> httpx.AsyncClient:
        """Retorna cliente HTTP reutilizável (lazy initialization)."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True
            )
        return self._http_client
    
    async def close(self):
        """Fecha o cliente HTTP (chamar no shutdown da aplicação)."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
    
    def _get_partition_url(self, prefix: str) -> str:
        """
        Constrói a URL para aceder a uma partição específica.
        
        Args:
            prefix: Prefixo do hash (ex: "ef", "a3")
            
        Returns:
            URL completa do ficheiro Parquet
        """
        return f"{settings.HF_DATASET_URL}/{prefix}.parquet"
    
    async def _fetch_partition(self, prefix: str) -> Optional[pd.DataFrame]:
        """
        Obtém uma partição do dataset remoto.
        
        Primeiro verifica o cache, se não existir, faz download
        e guarda no cache.
        
        Args:
            prefix: Prefixo da partição (ex: "ef")
            
        Returns:
            DataFrame com os dados da partição ou None se não existir
        """
        # Verificar cache primeiro
        if prefix in self._cache:
            logger.debug(f"Cache HIT para prefixo '{prefix}'")
            return self._cache[prefix]
        
        logger.debug(f"Cache MISS para prefixo '{prefix}', a fazer download...")
        
        try:
            # Obter cliente HTTP
            client = await self._get_http_client()
            
            # Construir URL
            url = self._get_partition_url(prefix)
            
            # Fazer request
            response = await client.get(url)
            
            # Verificar se existe
            if response.status_code == 404:
                logger.warning(f"Partição '{prefix}' não encontrada")
                return None
            
            response.raise_for_status()
            
            # Ler Parquet diretamente dos bytes
            df = pd.read_parquet(BytesIO(response.content))
            
            # Guardar no cache
            self._cache[prefix] = df
            
            logger.info(f"Partição '{prefix}' carregada: {len(df)} registos")
            
            return df
            
        except httpx.HTTPStatusError as e:
            logger.error(f"Erro HTTP ao obter partição '{prefix}': {e}")
            return None
        except Exception as e:
            logger.error(f"Erro ao processar partição '{prefix}': {e}")
            return None
    
    async def get_metadata(self) -> Optional[Dict]:
        """
        Obtém metadados do dataset.
        
        Returns:
            Dicionário com metadados ou None se não existir
        """
        # Verificar cache de metadados (recarregar a cada hora)
        if self._metadata_cache and self._metadata_timestamp:
            age = datetime.now() - self._metadata_timestamp
            if age < timedelta(hours=1):
                return self._metadata_cache
        
        try:
            client = await self._get_http_client()
            url = f"{settings.HF_DATASET_URL}/metadata.json"
            
            response = await client.get(url)
            
            if response.status_code == 404:
                logger.warning("Ficheiro metadata.json não encontrado")
                return None
            
            response.raise_for_status()
            
            self._metadata_cache = response.json()
            self._metadata_timestamp = datetime.now()
            
            return self._metadata_cache
            
        except Exception as e:
            logger.error(f"Erro ao obter metadados: {e}")
            return None
    
    async def check_breaches(self, prefix: str) -> List[Dict]:
        """
        Verifica breaches para um prefixo de hash.
        
        Esta é a função principal chamada pelo endpoint da API.
        
        Args:
            prefix: Prefixo do hash SHA-256 (2-6 caracteres hex)
            
        Returns:
            Lista de dicionários com informações dos breaches
            
        Exemplo de resposta:
            [
                {
                    "hash": "ef7241abc...",
                    "breach_name": "LinkedIn2021",
                    "breach_date": "2021-06-22",
                    "data_classes": ["email", "password"]
                },
                ...
            ]
        """
        # Normalizar prefixo para minúsculas
        prefix = prefix.lower()
        
        # Determinar qual partição carregar
        # O dataset está particionado pelos primeiros 2 caracteres
        partition_prefix = prefix[:2]
        
        # Obter partição
        df = await self._fetch_partition(partition_prefix)
        
        if df is None or df.empty:
            logger.info(f"Nenhum resultado para prefixo '{prefix}'")
            return []
        
        # Filtrar pelo prefixo completo (pode ser mais longo que 2 chars)
        # Isto permite pesquisas mais específicas
        mask = df["hash"].str.startswith(prefix)
        filtered_df = df[mask]
        
        if filtered_df.empty:
            logger.info(f"Nenhum match para prefixo '{prefix}'")
            return []
        
        # Converter para lista de dicionários
        results = []
        for _, row in filtered_df.iterrows():
            # Processar data_classes (pode ser string separada por vírgulas)
            data_classes = row.get("data_classes", "")
            if isinstance(data_classes, str):
                data_classes = [dc.strip() for dc in data_classes.split(",")]
            
            results.append({
                "hash": row["hash"],
                "breach_name": row.get("breach_name", "Unknown"),
                "breach_date": row.get("breach_date", "Unknown"),
                "data_classes": data_classes
            })
        
        logger.info(f"Encontrados {len(results)} resultados para prefixo '{prefix}'")
        
        return results
    
    def get_cache_stats(self) -> Dict:
        """
        Retorna estatísticas do cache.
        
        Returns:
            Dicionário com estatísticas
        """
        return {
            "size": len(self._cache),
            "max_size": self._cache.maxsize,
            "ttl_seconds": self._cache.ttl
        }


# ===========================================
# INSTÂNCIA SINGLETON
# ===========================================

# Instância global do serviço (singleton)
_breach_service: Optional[BreachService] = None


def get_breach_service() -> BreachService:
    """
    Retorna instância singleton do BreachService.
    
    Returns:
        Instância do BreachService
    """
    global _breach_service
    if _breach_service is None:
        _breach_service = BreachService()
    return _breach_service
