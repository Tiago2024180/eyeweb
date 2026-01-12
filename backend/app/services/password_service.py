"""
===========================================
Eye Web Backend — Password Service
===========================================

Serviço para verificação de passwords em fugas de dados.
Usa o mesmo modelo de K-Anonymity e particionamento por prefixo
que o serviço de breaches.

Dataset esperado: Samezinho/eye-web-passwords (ou configurável)
Formato: Parquet particionado por prefixo do hash
"""

import logging
import os
from functools import lru_cache
from typing import List, Dict, Any, Optional

from huggingface_hub import hf_hub_download, HfApi
from huggingface_hub.utils import EntryNotFoundError, RepositoryNotFoundError
import pandas as pd

from ..config import get_settings

logger = logging.getLogger(__name__)


class PasswordService:
    """
    Serviço para verificar passwords em fugas de dados.
    
    Implementa K-Anonymity através de particionamento por prefixo:
    - O dataset está dividido em ficheiros por prefixo (ex: ab.parquet)
    - Apenas o ficheiro correspondente ao prefixo é carregado
    - O servidor nunca vê a password ou o hash completo
    """
    
    def __init__(self):
        self.settings = get_settings()
        self._api = HfApi()
        self._cache: Dict[str, pd.DataFrame] = {}
        
        # Usar um dataset separado para passwords (configurável)
        self.repo_id = os.getenv("HF_PASSWORD_DATASET", "Samezinho/eye-web-passwords")
    
    def dataset_exists(self) -> bool:
        """
        Verifica se o dataset de passwords existe no Hugging Face.
        """
        try:
            self._api.repo_info(repo_id=self.repo_id, repo_type="dataset")
            return True
        except RepositoryNotFoundError:
            logger.warning(f"Dataset de passwords não encontrado: {self.repo_id}")
            return False
        except Exception as e:
            logger.error(f"Erro ao verificar dataset de passwords: {e}")
            return False
    
    async def get_passwords_by_prefix(self, prefix: str) -> List[Dict[str, Any]]:
        """
        Obtém todas as passwords cujo hash começa com o prefixo dado.
        
        Args:
            prefix: Primeiros N caracteres do hash SHA-256
            
        Returns:
            Lista de dicionários com informação das passwords
        """
        # Usar apenas os primeiros 2 caracteres para particionamento
        partition_prefix = prefix[:2].lower()
        
        try:
            # Verificar cache
            if partition_prefix in self._cache:
                df = self._cache[partition_prefix]
            else:
                # Descarregar o ficheiro da partição
                file_path = hf_hub_download(
                    repo_id=self.repo_id,
                    filename=f"{partition_prefix}.parquet",
                    repo_type="dataset",
                )
                
                # Carregar para DataFrame
                df = pd.read_parquet(file_path)
                
                # Guardar em cache (limite de memória)
                if len(self._cache) < 50:  # Máximo 50 partições em cache
                    self._cache[partition_prefix] = df
            
            # Filtrar por prefixo mais específico se necessário
            if len(prefix) > 2:
                mask = df['hash'].str.startswith(prefix.lower())
                df = df[mask]
            
            # Converter para lista de dicionários
            candidates = []
            for _, row in df.iterrows():
                candidates.append({
                    "hash": row["hash"],
                    "breach_count": row.get("breach_count", 1),
                })
            
            logger.debug(f"✅ Encontradas {len(candidates)} passwords com prefixo {prefix}")
            return candidates
            
        except EntryNotFoundError:
            logger.debug(f"ℹ️ Partição {partition_prefix} não existe (nenhuma password com este prefixo)")
            return []
        except Exception as e:
            logger.error(f"❌ Erro ao buscar passwords: {e}")
            return []
    
    async def get_stats(self) -> Dict[str, Any]:
        """
        Obtém estatísticas do dataset de passwords.
        """
        try:
            # Obter info do repo
            info = self._api.repo_info(repo_id=self.repo_id, repo_type="dataset")
            
            # Contar ficheiros
            files = self._api.list_repo_files(repo_id=self.repo_id, repo_type="dataset")
            parquet_files = [f for f in files if f.endswith('.parquet')]
            
            return {
                "total_partitions": len(parquet_files),
                "last_modified": str(info.lastModified) if info.lastModified else None,
            }
        except Exception as e:
            logger.error(f"Erro ao obter stats: {e}")
            return {
                "total_partitions": 0,
                "error": str(e)
            }


# ===========================================
# SINGLETON
# ===========================================

_password_service: Optional[PasswordService] = None


def get_password_service() -> PasswordService:
    """
    Obtém a instância singleton do serviço de passwords.
    """
    global _password_service
    if _password_service is None:
        _password_service = PasswordService()
    return _password_service
