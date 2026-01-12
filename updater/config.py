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
# Dividido entre emails e telefones
SYNTHETIC_EMAIL_RECORDS = 7000
SYNTHETIC_PHONE_RECORDS = 3000

# Tipos de dados suportados
DATA_TYPES = ["email", "phone"]

# ===========================================
# CÓDIGOS DE PAÍS PARA TELEFONES
# ===========================================

# Lista completa de códigos de país com informações de validação
# Formato: código -> (nome_país, min_dígitos, max_dígitos)
COUNTRY_PHONE_CODES = {
    # Europa
    "+351": ("Portugal", 9, 9),
    "+34": ("Espanha", 9, 9),
    "+33": ("França", 9, 9),
    "+44": ("Reino Unido", 10, 10),
    "+49": ("Alemanha", 10, 11),
    "+39": ("Itália", 9, 10),
    "+31": ("Países Baixos", 9, 9),
    "+32": ("Bélgica", 9, 9),
    "+41": ("Suíça", 9, 9),
    "+43": ("Áustria", 10, 10),
    "+48": ("Polónia", 9, 9),
    "+46": ("Suécia", 9, 9),
    "+47": ("Noruega", 8, 8),
    "+45": ("Dinamarca", 8, 8),
    "+358": ("Finlândia", 9, 10),
    "+353": ("Irlanda", 9, 9),
    "+30": ("Grécia", 10, 10),
    "+420": ("República Checa", 9, 9),
    "+36": ("Hungria", 9, 9),
    "+40": ("Roménia", 9, 9),
    "+380": ("Ucrânia", 9, 9),
    "+7": ("Rússia", 10, 10),
    # América do Norte
    "+1": ("EUA/Canadá", 10, 10),
    "+52": ("México", 10, 10),
    # América do Sul
    "+55": ("Brasil", 10, 11),
    "+54": ("Argentina", 10, 10),
    "+56": ("Chile", 9, 9),
    "+57": ("Colômbia", 10, 10),
    "+58": ("Venezuela", 10, 10),
    "+51": ("Peru", 9, 9),
    # Ásia
    "+86": ("China", 11, 11),
    "+91": ("Índia", 10, 10),
    "+81": ("Japão", 10, 10),
    "+82": ("Coreia do Sul", 9, 10),
    "+84": ("Vietname", 9, 10),
    "+66": ("Tailândia", 9, 9),
    "+60": ("Malásia", 9, 10),
    "+65": ("Singapura", 8, 8),
    "+62": ("Indonésia", 9, 12),
    "+63": ("Filipinas", 10, 10),
    "+971": ("Emirados Árabes", 9, 9),
    "+966": ("Arábia Saudita", 9, 9),
    "+972": ("Israel", 9, 9),
    "+90": ("Turquia", 10, 10),
    # África
    "+27": ("África do Sul", 9, 9),
    "+20": ("Egito", 10, 10),
    "+234": ("Nigéria", 10, 10),
    "+254": ("Quénia", 9, 9),
    "+212": ("Marrocos", 9, 9),
    # Oceânia
    "+61": ("Austrália", 9, 9),
    "+64": ("Nova Zelândia", 9, 10),
}

# Lista de breaches fictícios para dados de teste
# NOVA ESTRUTURA: com campos booleanos individuais para simular dados reais
SAMPLE_BREACHES = [
    {
        "name": "ExampleSite2024",
        "date": "2024-03-15",
        "has_password": True,
        "has_ip": False,
        "has_username": True,
        "has_credit_card": False,
        "has_history": False
    },
    {
        "name": "DemoApp2023",
        "date": "2023-11-20",
        "has_password": False,
        "has_ip": True,
        "has_username": False,
        "has_credit_card": False,
        "has_history": True
    },
    {
        "name": "TestService2024",
        "date": "2024-01-10",
        "has_password": True,
        "has_ip": True,
        "has_username": True,
        "has_credit_card": False,
        "has_history": False
    },
    {
        "name": "SampleDB2022",
        "date": "2022-08-05",
        "has_password": True,
        "has_ip": False,
        "has_username": True,
        "has_credit_card": False,
        "has_history": False
    },
    {
        "name": "MockPlatform2024",
        "date": "2024-06-22",
        "has_password": False,
        "has_ip": False,
        "has_username": False,
        "has_credit_card": True,
        "has_history": True
    },
    {
        "name": "FinanceLeaks2023",
        "date": "2023-09-01",
        "has_password": True,
        "has_ip": True,
        "has_username": True,
        "has_credit_card": True,
        "has_history": True
    },
    {
        "name": "SocialMediaBreach2024",
        "date": "2024-05-18",
        "has_password": True,
        "has_ip": True,
        "has_username": True,
        "has_credit_card": False,
        "has_history": True
    },
    {
        "name": "EcommerceHack2023",
        "date": "2023-12-03",
        "has_password": False,
        "has_ip": False,
        "has_username": False,
        "has_credit_card": True,
        "has_history": True
    },
    {
        "name": "GamingDB2024",
        "date": "2024-02-28",
        "has_password": True,
        "has_ip": True,
        "has_username": True,
        "has_credit_card": False,
        "has_history": False
    },
    {
        "name": "HealthcareExposure2023",
        "date": "2023-07-14",
        "has_password": False,
        "has_ip": True,
        "has_username": False,
        "has_credit_card": False,
        "has_history": True
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
