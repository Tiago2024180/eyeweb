#!/usr/bin/env python3
"""
===========================================
Eye Web Password Updater
===========================================

Script para gerar e fazer upload do dataset de passwords
vazadas para o Hugging Face.

Usa K-Anonymity através de:
- Hash SHA-256 de cada password
- Particionamento por prefixo do hash (2 chars = 256 ficheiros)
- O servidor nunca vê a password original

Execução:
    python password_updater.py

Antes de executar:
    1. Criar repositório no Hugging Face: Samezinho/eye-web-passwords
    2. Configurar HF_TOKEN no .env ou variável de ambiente
"""

import os
import sys
import random
import string
import hashlib
import logging
from pathlib import Path
from typing import List, Dict

import pandas as pd
from tqdm import tqdm
from huggingface_hub import HfApi, login

from password_config import (
    HF_TOKEN,
    HF_PASSWORD_REPO,
    HF_BRANCH,
    PREFIX_LENGTH,
    HEX_CHARS,
    DATA_DIR,
    OUTPUT_DIR,
    PARQUET_COMPRESSION,
    TEST_PASSWORDS,
    SYNTHETIC_PASSWORD_COUNT,
    COMMON_PATTERNS,
    validate_config,
    print_config_summary,
)

# ===========================================
# CONFIGURAÇÃO DE LOGGING
# ===========================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)


# ===========================================
# FUNÇÕES AUXILIARES
# ===========================================

def generate_sha256_hash(text: str) -> str:
    """Gera hash SHA-256 de uma string."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def get_hash_prefix(hash_value: str) -> str:
    """Obtém o prefixo do hash para particionamento."""
    return hash_value[:PREFIX_LENGTH].lower()


def generate_random_password() -> str:
    """Gera uma password aleatória seguindo padrões comuns."""
    pattern_type = random.choice([
        'pattern',      # Usar padrão comum
        'simple',       # Palavra + números
        'keyboard',     # Sequência de teclado
        'date',         # Data/ano
        'word_num',     # Palavra simples + número
    ])
    
    if pattern_type == 'pattern':
        pattern = random.choice(COMMON_PATTERNS)
        num = random.randint(1, 9999)
        year = random.randint(1970, 2024)
        return pattern.replace('{num}', str(num)).replace('{year}', str(year))
    
    elif pattern_type == 'simple':
        words = ['pass', 'user', 'admin', 'login', 'senha', 'teste', 'guest']
        return random.choice(words) + str(random.randint(1, 999))
    
    elif pattern_type == 'keyboard':
        sequences = ['qwerty', 'asdfgh', 'zxcvbn', '123456', '654321', 'qazwsx']
        return random.choice(sequences) + str(random.randint(0, 99))
    
    elif pattern_type == 'date':
        day = random.randint(1, 28)
        month = random.randint(1, 12)
        year = random.randint(1970, 2024)
        formats = [
            f"{day:02d}{month:02d}{year}",
            f"{year}{month:02d}{day:02d}",
            f"{day:02d}{month:02d}",
            f"{year}",
        ]
        return random.choice(formats)
    
    else:  # word_num
        words = ['love', 'baby', 'angel', 'hello', 'world', 'star', 'moon', 'sun']
        return random.choice(words) + str(random.randint(1, 999))


def generate_password_dataset() -> pd.DataFrame:
    """
    Gera o dataset de passwords para verificação.
    
    Returns:
        DataFrame com colunas:
        - hash: Hash SHA-256 da password
        - prefix: Prefixo do hash (para particionamento)
        - breach_count: Número de vezes que foi vista (simulado)
    """
    logger.info(f"🔄 A gerar dataset de passwords...")
    
    records = []
    seen_hashes = set()
    
    # 1. Adicionar passwords de teste conhecidas
    logger.info(f"📌 A adicionar {len(TEST_PASSWORDS)} passwords de teste...")
    for pwd in TEST_PASSWORDS:
        pwd_hash = generate_sha256_hash(pwd)
        prefix = get_hash_prefix(pwd_hash)
        
        if pwd_hash not in seen_hashes:
            records.append({
                "hash": pwd_hash,
                "prefix": prefix,
                "breach_count": random.randint(100, 10000),  # Simulado
            })
            seen_hashes.add(pwd_hash)
            logger.debug(f"   ✅ '{pwd}' -> prefix={prefix}")
    
    # 2. Gerar passwords sintéticas
    logger.info(f"🔄 A gerar {SYNTHETIC_PASSWORD_COUNT} passwords sintéticas...")
    for _ in tqdm(range(SYNTHETIC_PASSWORD_COUNT), desc="Passwords", unit="pwd"):
        pwd = generate_random_password()
        pwd_hash = generate_sha256_hash(pwd)
        
        # Evitar duplicados
        if pwd_hash in seen_hashes:
            continue
        
        prefix = get_hash_prefix(pwd_hash)
        
        records.append({
            "hash": pwd_hash,
            "prefix": prefix,
            "breach_count": random.randint(1, 1000),
        })
        seen_hashes.add(pwd_hash)
    
    logger.info(f"✅ Dataset gerado com {len(records)} passwords únicas")
    
    return pd.DataFrame(records)


def partition_dataset(df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    """
    Particiona o dataset por prefixo do hash.
    
    Args:
        df: DataFrame com coluna 'prefix'
        
    Returns:
        Dicionário {prefixo: DataFrame}
    """
    logger.info(f"📂 A particionar dataset por prefixo...")
    
    # Criar diretório de saída
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    
    partitions = {}
    
    for prefix, group in tqdm(df.groupby('prefix'), desc="Particionando", unit="partições"):
        # Guardar ficheiro Parquet
        output_file = os.path.join(OUTPUT_DIR, f"{prefix}.parquet")
        
        # Remover coluna prefix antes de guardar (redundante no nome do ficheiro)
        group_clean = group.drop(columns=['prefix'])
        group_clean.to_parquet(output_file, compression=PARQUET_COMPRESSION, index=False)
        
        partitions[prefix] = group_clean
    
    logger.info(f"✅ Particionamento completo! {len(partitions)} partições criadas")
    
    return partitions


def upload_to_huggingface():
    """Faz upload do dataset particionado para o Hugging Face."""
    logger.info(f"☁️ A iniciar upload para Hugging Face...")
    logger.info(f"   Repositório: {HF_PASSWORD_REPO}")
    
    # Autenticação
    login(token=HF_TOKEN)
    api = HfApi()
    
    # Verificar/criar repositório
    try:
        api.repo_info(repo_id=HF_PASSWORD_REPO, repo_type="dataset")
        logger.info(f"   ✅ Repositório encontrado")
    except Exception:
        logger.info(f"   📦 A criar repositório...")
        api.create_repo(repo_id=HF_PASSWORD_REPO, repo_type="dataset", private=False)
        logger.info(f"   ✅ Repositório criado")
    
    # Upload dos ficheiros
    logger.info(f"   📤 A fazer upload de ficheiros Parquet...")
    
    api.upload_folder(
        folder_path=OUTPUT_DIR,
        repo_id=HF_PASSWORD_REPO,
        repo_type="dataset",
        commit_message="Update password dataset",
    )
    
    logger.info(f"✅ Upload completo!")
    logger.info(f"   🔗 https://huggingface.co/datasets/{HF_PASSWORD_REPO}")


def main():
    """Função principal."""
    print("\n" + "="*60)
    print("👁️  EYE WEB PASSWORD UPDATER")
    print("="*60)
    
    # Mostrar configuração
    print_config_summary()
    
    # Validar configuração
    valid, message = validate_config()
    if not valid:
        logger.error(f"❌ Configuração inválida:\n{message}")
        sys.exit(1)
    logger.info(message)
    
    # Criar diretórios
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    
    # === FASE 1: Geração ===
    logger.info("\n" + "-"*40)
    logger.info("FASE 1: Geração do Dataset")
    logger.info("-"*40)
    
    df = generate_password_dataset()
    
    # === FASE 2: Particionamento ===
    logger.info("\n" + "-"*40)
    logger.info("FASE 2: Particionamento")
    logger.info("-"*40)
    
    partitions = partition_dataset(df)
    
    # === FASE 3: Upload ===
    logger.info("\n" + "-"*40)
    logger.info("FASE 3: Upload")
    logger.info("-"*40)
    
    upload_to_huggingface()
    
    # Resumo final
    print("\n" + "="*60)
    print("✅ DATASET DE PASSWORDS ATUALIZADO COM SUCESSO!")
    print(f"   Total: {len(df)} passwords")
    print(f"   Partições: {len(partitions)}")
    print(f"   URL: https://huggingface.co/datasets/{HF_PASSWORD_REPO}")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
