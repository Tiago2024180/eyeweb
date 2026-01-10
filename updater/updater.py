#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================
Eye Web Updater — Script Principal (Fase 1)
===========================================

Este script é responsável por:
1. Gerar/processar dados de breaches (sintéticos ou reais)
2. Normalizar emails e gerar hashes SHA-256
3. Particionar os dados por prefixo do hash
4. Comprimir em formato Apache Parquet (Snappy)
5. Fazer upload automático para o Hugging Face Datasets

Execução:
    python updater.py

Variáveis de Ambiente Necessárias:
    HF_TOKEN: Token do Hugging Face com permissão de escrita
    HF_DATASET_REPO: Nome do repositório (username/repo-name)

Autor: Eye Web PAP Project
Data: Janeiro 2026
"""

import os
import sys
import hashlib
import random
import string
import logging
from datetime import datetime
from typing import Dict, List, Optional

import pandas as pd
from tqdm import tqdm
from huggingface_hub import HfApi, login

# Importar configurações do projeto
from config import (
    HF_TOKEN,
    HF_DATASET_REPO,
    HF_BRANCH,
    PREFIX_LENGTH,
    HEX_CHARS,
    DATA_DIR,
    OUTPUT_DIR,
    PARQUET_COMPRESSION,
    SYNTHETIC_RECORDS,
    SAMPLE_BREACHES,
    LOG_LEVEL,
    LOG_DATE_FORMAT,
    validate_config,
    print_config_summary
)


# ===========================================
# CONFIGURAÇÃO DE LOGGING
# ===========================================

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=f"%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt=LOG_DATE_FORMAT
)
logger = logging.getLogger(__name__)


# ===========================================
# FUNÇÕES UTILITÁRIAS
# ===========================================

def normalize_email(email: str) -> str:
    """
    Normaliza um email para garantir consistência no hashing.
    
    Operações realizadas:
    - Converte para minúsculas
    - Remove espaços em branco
    - Remove pontos do username do Gmail (opcional)
    
    Args:
        email: Email original a normalizar
        
    Returns:
        str: Email normalizado
        
    Exemplo:
        >>> normalize_email("  Teste.User@Gmail.com  ")
        "testeuser@gmail.com"
    """
    # Remover espaços e converter para minúsculas
    email = email.strip().lower()
    
    # Tratamento especial para Gmail (pontos são ignorados)
    # Exemplo: john.doe@gmail.com == johndoe@gmail.com
    if "@gmail.com" in email:
        username, domain = email.split("@")
        username = username.replace(".", "")
        # Remover sufixo + (aliases do Gmail)
        username = username.split("+")[0]
        email = f"{username}@{domain}"
    
    return email


def generate_sha256_hash(text: str) -> str:
    """
    Gera o hash SHA-256 de um texto.
    
    Args:
        text: Texto a ser hasheado (ex: email normalizado)
        
    Returns:
        str: Hash SHA-256 em hexadecimal (64 caracteres)
        
    Exemplo:
        >>> generate_sha256_hash("teste@exemplo.com")
        "a1b2c3d4e5f6..."  # 64 chars hexadecimais
    """
    # Codificar o texto em bytes (UTF-8)
    text_bytes = text.encode('utf-8')
    
    # Criar objeto hash SHA-256
    hash_object = hashlib.sha256(text_bytes)
    
    # Retornar representação hexadecimal
    return hash_object.hexdigest()


def get_hash_prefix(hash_value: str, length: int = PREFIX_LENGTH) -> str:
    """
    Extrai o prefixo de um hash para particionamento.
    
    Args:
        hash_value: Hash SHA-256 completo
        length: Número de caracteres do prefixo
        
    Returns:
        str: Prefixo do hash (ex: "ef", "a3", "00")
        
    Exemplo:
        >>> get_hash_prefix("ef7241abc...", 2)
        "ef"
    """
    return hash_value[:length].lower()


# ===========================================
# GERAÇÃO DE DADOS SINTÉTICOS
# ===========================================

def generate_random_email() -> str:
    """
    Gera um email aleatório para dados de teste.
    
    Returns:
        str: Email aleatório no formato user123@domain.com
    """
    # Domínios comuns para simular
    domains = [
        "gmail.com", "hotmail.com", "yahoo.com", "outlook.com",
        "example.com", "test.org", "demo.net", "sample.io"
    ]
    
    # Gerar username aleatório
    username_length = random.randint(6, 12)
    username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=username_length))
    
    # Selecionar domínio aleatório
    domain = random.choice(domains)
    
    return f"{username}@{domain}"


def generate_synthetic_dataset(num_records: int = SYNTHETIC_RECORDS) -> pd.DataFrame:
    """
    Gera um dataset sintético de breaches para testes/demonstração.
    
    NOTA: Em produção, esta função seria substituída por uma que
    obtém dados reais de APIs públicas (ex: HIBP API, se disponível).
    
    Args:
        num_records: Número de registos a gerar
        
    Returns:
        pd.DataFrame: Dataset com colunas:
            - hash: Hash SHA-256 do email
            - prefix: Prefixo do hash (para particionamento)
            - breach_name: Nome do breach
            - breach_date: Data do breach
            - data_classes: Tipos de dados expostos
    """
    logger.info(f"🔄 A gerar {num_records:,} registos sintéticos...")
    
    records = []
    
    # Usar tqdm para mostrar progresso
    for _ in tqdm(range(num_records), desc="Gerando dados", unit="registos"):
        # Gerar email aleatório
        email = generate_random_email()
        
        # Normalizar e gerar hash
        normalized_email = normalize_email(email)
        email_hash = generate_sha256_hash(normalized_email)
        prefix = get_hash_prefix(email_hash)
        
        # Selecionar breach aleatório
        breach = random.choice(SAMPLE_BREACHES)
        
        # Criar registo
        record = {
            "hash": email_hash,
            "prefix": prefix,
            "breach_name": breach["name"],
            "breach_date": breach["date"],
            "data_classes": ",".join(breach["data_classes"])  # Serializar lista como string
        }
        
        records.append(record)
    
    # Criar DataFrame
    df = pd.DataFrame(records)
    
    logger.info(f"✅ Dataset gerado com {len(df):,} registos")
    logger.info(f"   Colunas: {list(df.columns)}")
    logger.info(f"   Prefixos únicos: {df['prefix'].nunique()}")
    
    return df


# ===========================================
# PARTICIONAMENTO DE DADOS
# ===========================================

def partition_dataset(df: pd.DataFrame, output_dir: str = OUTPUT_DIR) -> Dict[str, str]:
    """
    Particiona o dataset por prefixo do hash e guarda em ficheiros Parquet.
    
    Cada partição é guardada num ficheiro separado (ex: ef.parquet, 00.parquet).
    Isto permite que a API leia apenas a partição necessária, otimizando
    o uso de memória no Render Free Tier (512MB).
    
    Args:
        df: DataFrame com os dados de breaches
        output_dir: Diretório onde guardar os ficheiros Parquet
        
    Returns:
        Dict[str, str]: Mapeamento {prefixo: caminho_ficheiro}
        
    Estrutura de Saída:
        output_dir/
        ├── 00.parquet
        ├── 01.parquet
        ├── ...
        ├── fe.parquet
        └── ff.parquet
    """
    logger.info(f"📂 A particionar dataset por prefixo (comprimento={PREFIX_LENGTH})...")
    
    # Criar diretório de saída se não existir
    os.makedirs(output_dir, exist_ok=True)
    
    # Agrupar por prefixo
    grouped = df.groupby("prefix")
    
    # Dicionário para guardar caminhos dos ficheiros
    partition_files = {}
    
    # Iterar por cada grupo (prefixo)
    for prefix, group_df in tqdm(grouped, desc="Particionando", unit="partições"):
        # Definir caminho do ficheiro
        file_path = os.path.join(output_dir, f"{prefix}.parquet")
        
        # Remover coluna de prefixo (já está no nome do ficheiro)
        partition_df = group_df.drop(columns=["prefix"])
        
        # Guardar em formato Parquet com compressão
        partition_df.to_parquet(
            file_path,
            engine="pyarrow",
            compression=PARQUET_COMPRESSION,
            index=False
        )
        
        partition_files[prefix] = file_path
        
        logger.debug(f"   {prefix}.parquet: {len(partition_df):,} registos")
    
    logger.info(f"✅ Particionamento completo!")
    logger.info(f"   Total de partições: {len(partition_files)}")
    logger.info(f"   Diretório: {output_dir}")
    
    return partition_files


# ===========================================
# UPLOAD PARA HUGGING FACE
# ===========================================

def upload_to_huggingface(
    output_dir: str = OUTPUT_DIR,
    repo_id: str = HF_DATASET_REPO,
    token: str = HF_TOKEN
) -> bool:
    """
    Faz upload da pasta completa de ficheiros Parquet para o Hugging Face.
    
    OTIMIZADO: Usa upload_folder para fazer tudo num único commit,
    evitando o limite de rate (128 commits/hora no plano gratuito).
    
    Args:
        output_dir: Diretório local com os ficheiros Parquet
        repo_id: ID do repositório no formato "username/repo-name"
        token: Token de autenticação do Hugging Face
        
    Returns:
        bool: True se o upload foi bem sucedido, False caso contrário
        
    Estrutura no Hugging Face:
        repo/
        └── data/
            ├── 00.parquet
            ├── 01.parquet
            └── ...
    """
    logger.info(f"☁️ A iniciar upload para Hugging Face...")
    logger.info(f"   Repositório: {repo_id}")
    logger.info(f"   Pasta local: {output_dir}")
    
    try:
        # Autenticar no Hugging Face
        login(token=token)
        logger.info("   ✅ Autenticação bem sucedida")
        
        # Criar instância da API
        api = HfApi()
        
        # Verificar se o repositório existe, se não, criar
        try:
            api.repo_info(repo_id=repo_id, repo_type="dataset")
            logger.info(f"   ✅ Repositório encontrado")
        except Exception:
            logger.info(f"   📁 A criar novo repositório...")
            api.create_repo(
                repo_id=repo_id,
                repo_type="dataset",
                private=False,  # Público para que a API possa aceder
                exist_ok=True
            )
            logger.info(f"   ✅ Repositório criado")
        
        # Contar ficheiros a enviar
        parquet_files = [f for f in os.listdir(output_dir) if f.endswith('.parquet')]
        logger.info(f"   📦 A preparar upload de {len(parquet_files)} ficheiros...")
        
        # Upload da pasta completa num único commit
        # Isto evita o limite de 128 commits/hora!
        api.upload_folder(
            folder_path=output_dir,
            path_in_repo="data",
            repo_id=repo_id,
            repo_type="dataset",
            commit_message=f"Update dataset: {len(parquet_files)} partitions"
        )
        
        logger.info(f"✅ Upload completo! {len(parquet_files)} ficheiros enviados.")
        logger.info(f"   🔗 https://huggingface.co/datasets/{repo_id}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Erro no upload: {str(e)}")
        return False


# ===========================================
# CRIAÇÃO DO FICHEIRO DE METADADOS
# ===========================================

def create_metadata_file(partition_files: Dict[str, str], output_dir: str = OUTPUT_DIR) -> str:
    """
    Cria um ficheiro JSON com metadados do dataset.
    
    Este ficheiro ajuda a API a saber quais partições existem
    e contém estatísticas úteis.
    
    Args:
        partition_files: Dicionário {prefixo: caminho_local}
        output_dir: Diretório de saída
        
    Returns:
        str: Caminho do ficheiro de metadados
    """
    import json
    
    # Calcular estatísticas
    total_records = 0
    partition_stats = {}
    
    for prefix, file_path in partition_files.items():
        df = pd.read_parquet(file_path)
        count = len(df)
        total_records += count
        partition_stats[prefix] = count
    
    # Criar metadados
    metadata = {
        "version": "1.0.0",
        "generated_at": datetime.now().isoformat(),
        "prefix_length": PREFIX_LENGTH,
        "compression": PARQUET_COMPRESSION,
        "total_records": total_records,
        "total_partitions": len(partition_files),
        "partitions": partition_stats
    }
    
    # Guardar ficheiro
    metadata_path = os.path.join(output_dir, "metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    
    logger.info(f"📋 Metadados guardados em: {metadata_path}")
    
    return metadata_path


def upload_metadata(metadata_path: str, repo_id: str = HF_DATASET_REPO, token: str = HF_TOKEN):
    """
    Faz upload do ficheiro de metadados para o Hugging Face.
    """
    api = HfApi()
    
    api.upload_file(
        path_or_fileobj=metadata_path,
        path_in_repo="data/metadata.json",
        repo_id=repo_id,
        repo_type="dataset",
        commit_message="Update metadata.json"
    )
    
    logger.info("📋 Metadados enviados para o Hugging Face")


# ===========================================
# LIMPEZA DE FICHEIROS TEMPORÁRIOS
# ===========================================

def cleanup_temp_files(output_dir: str = OUTPUT_DIR):
    """
    Remove ficheiros temporários após o upload.
    
    Args:
        output_dir: Diretório a limpar
    """
    import shutil
    
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
        logger.info(f"🧹 Ficheiros temporários removidos: {output_dir}")


# ===========================================
# FUNÇÃO PRINCIPAL
# ===========================================

def main():
    """
    Função principal que orquestra todo o processo de atualização.
    
    Fluxo:
    1. Validar configuração
    2. Gerar/obter dados
    3. Particionar por prefixo
    4. Criar metadados
    5. Upload para Hugging Face
    6. Limpeza
    """
    print("\n" + "="*60)
    print("👁️  EYE WEB UPDATER — Breach Dataset Pipeline")
    print("="*60)
    
    # Mostrar configuração
    print_config_summary()
    
    # 1. Validar configuração
    logger.info("🔍 A validar configuração...")
    is_valid, message = validate_config()
    
    if not is_valid:
        logger.error(f"❌ Configuração inválida:\n{message}")
        sys.exit(1)
    
    logger.info(message)
    
    # 2. Gerar dados sintéticos (em produção, seria obter dados reais)
    logger.info("\n" + "-"*40)
    logger.info("FASE 1: Geração de Dados")
    logger.info("-"*40)
    
    df = generate_synthetic_dataset()
    
    # 3. Particionar dataset
    logger.info("\n" + "-"*40)
    logger.info("FASE 2: Particionamento")
    logger.info("-"*40)
    
    partition_files = partition_dataset(df)
    
    # 4. Criar metadados
    logger.info("\n" + "-"*40)
    logger.info("FASE 3: Metadados")
    logger.info("-"*40)
    
    metadata_path = create_metadata_file(partition_files)
    
    # 5. Upload para Hugging Face
    logger.info("\n" + "-"*40)
    logger.info("FASE 4: Upload")
    logger.info("-"*40)
    
    # Usa upload_folder para evitar limite de rate (128 commits/hora)
    success = upload_to_huggingface(OUTPUT_DIR)
    
    if success:
        upload_metadata(metadata_path)
    
    # 6. Limpeza (opcional - comentar se quiseres manter os ficheiros)
    # cleanup_temp_files()
    
    # Resumo final
    print("\n" + "="*60)
    if success:
        print("✅ ATUALIZAÇÃO CONCLUÍDA COM SUCESSO!")
        print(f"   Dataset disponível em:")
        print(f"   https://huggingface.co/datasets/{HF_DATASET_REPO}")
    else:
        print("❌ ATUALIZAÇÃO FALHOU - Verificar logs acima")
    print("="*60 + "\n")
    
    return 0 if success else 1


# ===========================================
# PONTO DE ENTRADA
# ===========================================

if __name__ == "__main__":
    sys.exit(main())
