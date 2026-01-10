# ===========================================
# Eye Web Updater — Configurações
# ===========================================
# Este ficheiro centraliza todas as configurações do script de atualização.
# Valores sensíveis (tokens) devem vir de variáveis de ambiente.

import os
from dotenv import load_dotenv

# Carregar variáveis de ambiente do ficheiro .env (se existir)
load_dotenv()


# ===========================================
# CONFIGURAÇÕES DO HUGGING FACE
# ===========================================

# Token de autenticação do Hugging Face (com permissão de WRITE)
# NUNCA colocar o token diretamente aqui em produção!
# Deve ser configurado via:
#   - Variável de ambiente: export HF_TOKEN=hf_xxxxx
#   - GitHub Secrets: HF_TOKEN
#   - Ficheiro .env local (apenas desenvolvimento)
HF_TOKEN = os.getenv("HF_TOKEN", "")

# Nome do repositório do dataset no Hugging Face
# Formato: "username/nome-do-repo"
HF_DATASET_REPO = os.getenv("HF_DATASET_REPO", "teu-username/eye-web-breaches")

# Branch do repositório (normalmente "main")
HF_BRANCH = os.getenv("HF_BRANCH", "main")


# ===========================================
# CONFIGURAÇÕES DE PARTICIONAMENTO
# ===========================================

# Número de caracteres do prefixo do hash para particionamento
# 1 char = 16 partições (0-f)
# 2 chars = 256 partições (00-ff)
# Recomendado: 2 para datasets grandes, 1 para datasets pequenos
PREFIX_LENGTH = 2

# Caracteres hexadecimais válidos para nomes de partições
HEX_CHARS = "0123456789abcdef"


# ===========================================
# CONFIGURAÇÕES DE FICHEIROS
# ===========================================

# Diretório temporário para processamento de dados
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# Diretório de saída para ficheiros Parquet
OUTPUT_DIR = os.path.join(DATA_DIR, "parquet_output")

# Compressão dos ficheiros Parquet
# Opções: "snappy" (rápido), "gzip" (menor tamanho), "zstd" (equilibrado)
PARQUET_COMPRESSION = "snappy"


# ===========================================
# CONFIGURAÇÕES DE DADOS SINTÉTICOS
# ===========================================

# Para desenvolvimento/testes, podemos gerar dados sintéticos
# Em produção, estes dados viriam de fontes reais (APIs públicas, etc.)

# Número de registos sintéticos a gerar (para testes)
SYNTHETIC_RECORDS = 10000

# Lista de breaches fictícios para dados de teste
SAMPLE_BREACHES = [
    {
        "name": "ExampleSite2024",
        "date": "2024-03-15",
        "data_classes": ["email", "password_hash", "username"]
    },
    {
        "name": "DemoApp2023", 
        "date": "2023-11-20",
        "data_classes": ["email", "phone", "address"]
    },
    {
        "name": "TestService2024",
        "date": "2024-01-10",
        "data_classes": ["email", "ip_address", "user_agent"]
    },
    {
        "name": "SampleDB2022",
        "date": "2022-08-05",
        "data_classes": ["email", "password", "full_name"]
    },
    {
        "name": "MockPlatform2024",
        "date": "2024-06-22",
        "data_classes": ["email", "credit_card_partial", "purchase_history"]
    }
]


# ===========================================
# CONFIGURAÇÕES DE LOGGING
# ===========================================

# Nível de logging: DEBUG, INFO, WARNING, ERROR
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Formato do timestamp nos logs
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


# ===========================================
# VALIDAÇÃO DE CONFIGURAÇÃO
# ===========================================

def validate_config():
    """
    Valida se todas as configurações obrigatórias estão definidas.
    Chama esta função no início do script principal.
    
    Returns:
        tuple: (bool: válido, str: mensagem de erro ou sucesso)
    """
    errors = []
    
    # Verificar token do Hugging Face
    if not HF_TOKEN:
        errors.append("HF_TOKEN não está definido. Configura a variável de ambiente.")
    
    # Verificar nome do repositório
    if not HF_DATASET_REPO or "/" not in HF_DATASET_REPO:
        errors.append("HF_DATASET_REPO inválido. Formato esperado: 'username/repo-name'")
    
    # Verificar se o prefixo é válido
    if PREFIX_LENGTH < 1 or PREFIX_LENGTH > 4:
        errors.append("PREFIX_LENGTH deve estar entre 1 e 4.")
    
    if errors:
        return False, "\n".join(errors)
    
    return True, "✅ Configuração válida!"


# ===========================================
# INFORMAÇÕES DE DEBUG
# ===========================================

def print_config_summary():
    """
    Imprime um resumo das configurações (sem expor segredos).
    Útil para debugging.
    """
    print("\n" + "="*50)
    print("📋 CONFIGURAÇÃO DO UPDATER")
    print("="*50)
    print(f"  HF_DATASET_REPO: {HF_DATASET_REPO}")
    print(f"  HF_TOKEN: {'✅ Definido' if HF_TOKEN else '❌ Não definido'}")
    print(f"  PREFIX_LENGTH: {PREFIX_LENGTH}")
    print(f"  PARQUET_COMPRESSION: {PARQUET_COMPRESSION}")
    print(f"  DATA_DIR: {DATA_DIR}")
    print(f"  OUTPUT_DIR: {OUTPUT_DIR}")
    print("="*50 + "\n")
