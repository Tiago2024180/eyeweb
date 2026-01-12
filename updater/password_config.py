# ===========================================
# Eye Web Password Updater — Configurações
# ===========================================
# Este ficheiro configura o script para gerar e fazer upload
# do dataset de passwords vazadas para o Hugging Face.
#
# O dataset usa a mesma estrutura de K-Anonymity:
# - Hash SHA-256 da password
# - Particionado por prefixo (2 chars = 256 partições)
# - Formato Parquet para eficiência

import os
from dotenv import load_dotenv

# Carregar variáveis de ambiente
load_dotenv()


# ===========================================
# CONFIGURAÇÕES DO HUGGING FACE
# ===========================================

# Token de autenticação do Hugging Face (com permissão de WRITE)
HF_TOKEN = os.getenv("HF_TOKEN", "")

# Nome do repositório do dataset de passwords
# NOTA: Este é um repositório SEPARADO do dataset de breaches!
HF_PASSWORD_REPO = os.getenv("HF_PASSWORD_REPO", "Samezinho/eye-web-passwords")

# Branch do repositório
HF_BRANCH = os.getenv("HF_BRANCH", "main")


# ===========================================
# CONFIGURAÇÕES DE PARTICIONAMENTO
# ===========================================

# Número de caracteres do prefixo do hash para particionamento
# 2 chars = 256 partições (00-ff)
PREFIX_LENGTH = 2

# Caracteres hexadecimais válidos
HEX_CHARS = "0123456789abcdef"


# ===========================================
# CONFIGURAÇÕES DE FICHEIROS
# ===========================================

# Diretório temporário para processamento
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# Diretório de saída para ficheiros Parquet
OUTPUT_DIR = os.path.join(DATA_DIR, "password_parquet")

# Compressão dos ficheiros Parquet
PARQUET_COMPRESSION = "snappy"


# ===========================================
# PASSWORDS DE TESTE CONHECIDAS
# ===========================================
# Estas passwords serão SEMPRE incluídas no dataset para testes
# IMPORTANTE: São passwords COMUNS que aparecem em listas de vazamentos reais

TEST_PASSWORDS = [
    "password",
    "123456",
    "123456789",
    "12345678",
    "qwerty",
    "abc123",
    "password1",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "login",
    "princess",
    "qwerty123",
    "senha123",          # Comum em Portugal/Brasil
    "portugal123",       # Comum em Portugal
    "benfica",           # Comum em Portugal
    "sporting",          # Comum em Portugal
    "password123",
    "iloveyou",
    "trustno1",
    "sunshine",
    "passw0rd",
]


# ===========================================
# CONFIGURAÇÕES DE GERAÇÃO SINTÉTICA
# ===========================================

# Para testes, podemos gerar passwords aleatórias adicionais
# Em produção, usarias uma lista real de passwords vazadas
SYNTHETIC_PASSWORD_COUNT = 5000

# Padrões comuns para gerar passwords sintéticas
COMMON_PATTERNS = [
    # nome + números
    "user{num}",
    "admin{num}",
    "guest{num}",
    # palavras + números
    "love{num}",
    "teste{num}",
    "hello{num}",
    # sequências
    "qwerty{num}",
    "asdfgh{num}",
    # datas
    "{year}",
    "pass{year}",
]


# ===========================================
# VALIDAÇÃO
# ===========================================

def validate_config():
    """Valida se as configurações estão corretas."""
    errors = []
    
    if not HF_TOKEN:
        errors.append("HF_TOKEN não está definido.")
    
    if not HF_PASSWORD_REPO or "/" not in HF_PASSWORD_REPO:
        errors.append("HF_PASSWORD_REPO inválido. Formato: 'username/repo-name'")
    
    if errors:
        return False, "\n".join(errors)
    
    return True, "✅ Configuração válida!"


def print_config_summary():
    """Imprime resumo das configurações."""
    print("\n" + "="*50)
    print("📋 CONFIGURAÇÃO DO PASSWORD UPDATER")
    print("="*50)
    print(f"  HF_PASSWORD_REPO: {HF_PASSWORD_REPO}")
    print(f"  HF_TOKEN: {'✅ Definido' if HF_TOKEN else '❌ Não definido'}")
    print(f"  PREFIX_LENGTH: {PREFIX_LENGTH}")
    print(f"  TEST_PASSWORDS: {len(TEST_PASSWORDS)} passwords de teste")
    print(f"  SYNTHETIC_COUNT: {SYNTHETIC_PASSWORD_COUNT}")
    print("="*50 + "\n")
