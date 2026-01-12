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
    SYNTHETIC_EMAIL_RECORDS,
    SYNTHETIC_PHONE_RECORDS,
    SAMPLE_BREACHES,
    COUNTRY_PHONE_CODES,
    DATA_TYPES,
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


def normalize_phone(phone: str, country_code: str = "") -> str:
    """
    Normaliza um número de telefone para garantir consistência no hashing.
    
    IMPORTANTE para K-Anonymity: O número completo (com código de país)
    deve ser normalizado antes de gerar o hash. O cliente (frontend)
    deve usar EXATAMENTE a mesma lógica de normalização.
    
    Operações realizadas:
    - Remove todos os espaços, hífens, parênteses
    - Garante que o código de país está presente
    - Garante formato: +XXXYYYYYYYYY (sem separadores)
    
    Args:
        phone: Número de telefone (pode ter formatação)
        country_code: Código do país (ex: "+351")
        
    Returns:
        str: Telefone normalizado no formato +XXXYYYYYYYYY
        
    Exemplo:
        >>> normalize_phone("912 341 801", "+351")
        "+351912341801"
        >>> normalize_phone("+351 912-341-801")
        "+351912341801"
    """
    # Remover todos os caracteres não numéricos, exceto o + inicial
    cleaned = ""
    for i, char in enumerate(phone):
        if char == "+" and i == 0:
            cleaned += char
        elif char.isdigit():
            cleaned += char
    
    # Se não começa com +, adicionar o código de país
    if not cleaned.startswith("+"):
        if country_code:
            # Garantir que o código de país começa com +
            if not country_code.startswith("+"):
                country_code = "+" + country_code
            cleaned = country_code + cleaned
        else:
            # Se não há código de país, assumir +351 (Portugal) como default
            cleaned = "+351" + cleaned
    
    return cleaned


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
        "example.com", "test.org", "demo.net", "sample.io",
        "protonmail.com", "icloud.com", "live.com", "mail.com"
    ]
    
    # Gerar username aleatório
    username_length = random.randint(6, 12)
    username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=username_length))
    
    # Selecionar domínio aleatório
    domain = random.choice(domains)
    
    return f"{username}@{domain}"


def generate_random_phone() -> tuple:
    """
    Gera um número de telefone aleatório com código de país.
    
    Returns:
        tuple: (telefone_completo_normalizado, código_país)
        
    Exemplo:
        >>> generate_random_phone()
        ("+351912345678", "+351")
    """
    # Selecionar código de país aleatório
    country_code = random.choice(list(COUNTRY_PHONE_CODES.keys()))
    country_name, min_digits, max_digits = COUNTRY_PHONE_CODES[country_code]
    
    # Gerar número com o comprimento correto para o país
    num_digits = random.randint(min_digits, max_digits)
    
    # Primeiro dígito não pode ser 0 para a maioria dos países
    first_digit = random.choice("123456789")
    remaining_digits = ''.join(random.choices(string.digits, k=num_digits - 1))
    
    phone_number = first_digit + remaining_digits
    
    # Normalizar (código + número, sem espaços)
    normalized = f"{country_code}{phone_number}"
    
    return normalized, country_code


# ===========================================
# DADOS DE TESTE CONHECIDOS (para verificação)
# ===========================================

# Emails que SABEMOS que estão na base de dados
# Usar estes para testar se o sistema deteta breaches corretamente
TEST_EMAILS = [
    ("leaked@test.com", "TestBreach2024", "2024-01-15"),
    ("hacked@example.com", "ExampleHack2023", "2023-06-20"),
    ("breach@demo.com", "DemoLeak2024", "2024-03-10"),
    ("exposed@sample.com", "SampleExposure2023", "2023-11-05"),
    ("pwned@eyeweb.test", "EyeWebTest2024", "2024-07-01"),
]

# Telefones que SABEMOS que estão na base de dados
# Formato: (número, código_país, breach_name, breach_date)
# IMPORTANTE: Usar estes números EXATAMENTE para testar
TEST_PHONES = [
    ("+351912345678", "DataBreach2024", "2024-01-20"),      # Portugal
    ("+351961234567", "SocialMediaBreach2024", "2024-05-18"),  # Portugal
    ("+34612345678", "EcommerceHack2023", "2023-12-03"),    # Espanha
    ("+44712345678", "GamingDB2024", "2024-02-28"),         # Reino Unido (exemplo: 07123456780 -> +447123456780)
    ("+5511912345678", "HealthcareExposure2023", "2023-07-14"),  # Brasil
]


def generate_synthetic_dataset() -> pd.DataFrame:
    """
    Gera um dataset sintético de breaches para testes/demonstração.
    
    NOVA ESTRUTURA com:
    - Suporte para emails E telefones
    - Campos booleanos individuais para cada tipo de dado exposto
    - Coluna 'type' para distinguir email de phone
    
    NOTA: Em produção, esta função seria substituída por uma que
    obtém dados reais de APIs públicas (ex: HIBP API, se disponível).
        
    Returns:
        pd.DataFrame: Dataset com colunas:
            - hash: Hash SHA-256 do email/phone
            - type: "email" ou "phone"
            - prefix: Prefixo do hash (para particionamento)
            - breach_name: Nome do breach
            - breach_date: Data do breach
            - has_password: Boolean
            - has_ip: Boolean
            - has_username: Boolean
            - has_credit_card: Boolean
            - has_history: Boolean
    """
    total_records = SYNTHETIC_EMAIL_RECORDS + SYNTHETIC_PHONE_RECORDS
    logger.info(f"🔄 A gerar {total_records:,} registos sintéticos...")
    logger.info(f"   📧 Emails: {SYNTHETIC_EMAIL_RECORDS:,}")
    logger.info(f"   📱 Telefones: {SYNTHETIC_PHONE_RECORDS:,}")
    
    records = []
    
    # ===========================================
    # PRIMEIRO: Adicionar dados de teste CONHECIDOS
    # ===========================================
    logger.info("📌 A adicionar emails de teste conhecidos...")
    for email, breach_name, breach_date in TEST_EMAILS:
        normalized = normalize_email(email)
        data_hash = generate_sha256_hash(normalized)
        prefix = get_hash_prefix(data_hash)
        
        record = {
            "hash": data_hash,
            "type": "email",
            "prefix": prefix,
            "breach_name": breach_name,
            "breach_date": breach_date,
            "has_password": True,
            "has_ip": True,
            "has_username": True,
            "has_credit_card": False,
            "has_history": True
        }
        records.append(record)
        logger.debug(f"   ✅ {email} -> prefix={prefix}")
    
    logger.info("📌 A adicionar telefones de teste conhecidos...")
    for phone, breach_name, breach_date in TEST_PHONES:
        # O telefone já está normalizado na lista
        data_hash = generate_sha256_hash(phone)
        prefix = get_hash_prefix(data_hash)
        
        record = {
            "hash": data_hash,
            "type": "phone",
            "prefix": prefix,
            "breach_name": breach_name,
            "breach_date": breach_date,
            "has_password": True,
            "has_ip": True,
            "has_username": False,
            "has_credit_card": True,
            "has_history": True
        }
        records.append(record)
        logger.debug(f"   ✅ {phone} -> prefix={prefix}")
    
    logger.info(f"   📌 Total de dados de teste: {len(TEST_EMAILS)} emails + {len(TEST_PHONES)} telefones")
    
    # ===========================================
    # DEPOIS: Gerar dados aleatórios
    # ===========================================
    
    # === GERAR REGISTOS DE EMAIL ===
    logger.info("📧 A gerar registos de email aleatórios...")
    for _ in tqdm(range(SYNTHETIC_EMAIL_RECORDS), desc="Emails", unit="registos"):
        # Gerar email aleatório
        email = generate_random_email()
        
        # Normalizar e gerar hash
        normalized = normalize_email(email)
        data_hash = generate_sha256_hash(normalized)
        prefix = get_hash_prefix(data_hash)
        
        # Selecionar breach aleatório
        breach = random.choice(SAMPLE_BREACHES)
        
        # Criar registo com a NOVA ESTRUTURA
        record = {
            "hash": data_hash,
            "type": "email",
            "prefix": prefix,
            "breach_name": breach["name"],
            "breach_date": breach["date"],
            "has_password": breach["has_password"],
            "has_ip": breach["has_ip"],
            "has_username": breach["has_username"],
            "has_credit_card": breach["has_credit_card"],
            "has_history": breach["has_history"]
        }
        
        records.append(record)
    
    # === GERAR REGISTOS DE TELEFONE ===
    logger.info("📱 A gerar registos de telefone aleatórios...")
    for _ in tqdm(range(SYNTHETIC_PHONE_RECORDS), desc="Telefones", unit="registos"):
        # Gerar telefone aleatório
        phone, country_code = generate_random_phone()
        
        # O telefone já vem normalizado da função
        data_hash = generate_sha256_hash(phone)
        prefix = get_hash_prefix(data_hash)
        
        # Selecionar breach aleatório
        breach = random.choice(SAMPLE_BREACHES)
        
        # Criar registo com a NOVA ESTRUTURA
        record = {
            "hash": data_hash,
            "type": "phone",
            "prefix": prefix,
            "breach_name": breach["name"],
            "breach_date": breach["date"],
            "has_password": breach["has_password"],
            "has_ip": breach["has_ip"],
            "has_username": breach["has_username"],
            "has_credit_card": breach["has_credit_card"],
            "has_history": breach["has_history"]
        }
        
        records.append(record)
    
    # Criar DataFrame
    df = pd.DataFrame(records)
    
    # Estatísticas finais
    logger.info(f"✅ Dataset gerado com {len(df):,} registos")
    logger.info(f"   Colunas: {list(df.columns)}")
    logger.info(f"   Prefixos únicos: {df['prefix'].nunique()}")
    logger.info(f"   Emails: {len(df[df['type'] == 'email']):,}")
    logger.info(f"   Telefones: {len(df[df['type'] == 'phone']):,}")
    
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
    total_emails = 0
    total_phones = 0
    partition_stats = {}
    
    for prefix, file_path in partition_files.items():
        df = pd.read_parquet(file_path)
        count = len(df)
        total_records += count
        
        # Contar por tipo se a coluna existir
        if 'type' in df.columns:
            email_count = len(df[df['type'] == 'email'])
            phone_count = len(df[df['type'] == 'phone'])
            total_emails += email_count
            total_phones += phone_count
            partition_stats[prefix] = {
                "total": count,
                "emails": email_count,
                "phones": phone_count
            }
        else:
            partition_stats[prefix] = {"total": count}
    
    # Criar metadados com a NOVA ESTRUTURA
    metadata = {
        "version": "2.0.0",  # Versão atualizada para nova estrutura
        "generated_at": datetime.now().isoformat(),
        "prefix_length": PREFIX_LENGTH,
        "compression": PARQUET_COMPRESSION,
        "schema": {
            "columns": [
                {"name": "hash", "type": "string", "description": "SHA-256 do email/phone normalizado"},
                {"name": "type", "type": "string", "description": "Tipo de dado: 'email' ou 'phone'"},
                {"name": "breach_name", "type": "string", "description": "Nome do breach"},
                {"name": "breach_date", "type": "string", "description": "Data do breach (YYYY-MM-DD)"},
                {"name": "has_password", "type": "boolean", "description": "Password foi exposta?"},
                {"name": "has_ip", "type": "boolean", "description": "IP foi exposto?"},
                {"name": "has_username", "type": "boolean", "description": "Username foi exposto?"},
                {"name": "has_credit_card", "type": "boolean", "description": "Cartão de crédito foi exposto?"},
                {"name": "has_history", "type": "boolean", "description": "Histórico foi exposto?"}
            ]
        },
        "statistics": {
            "total_records": total_records,
            "total_emails": total_emails,
            "total_phones": total_phones,
            "total_partitions": len(partition_files)
        },
        "partitions": partition_stats
    }
    
    # Guardar ficheiro
    metadata_path = os.path.join(output_dir, "metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    
    logger.info(f"📋 Metadados guardados em: {metadata_path}")
    logger.info(f"   Total: {total_records:,} registos")
    logger.info(f"   Emails: {total_emails:,}")
    logger.info(f"   Telefones: {total_phones:,}")
    
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
