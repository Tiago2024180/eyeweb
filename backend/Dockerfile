# ===========================================
# Dockerfile — Eye Web Backend (FastAPI)
# ===========================================
# Imagem otimizada para o Render Free Tier (512MB RAM)

# Usar imagem slim do Python (versão específica para estabilidade)
# Atualizar manualmente quando necessário: https://hub.docker.com/_/python
FROM python:3.11.7-slim

# Definir variáveis de ambiente
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Criar utilizador não-root para segurança
RUN useradd --create-home --shell /bin/bash appuser

# Definir diretório de trabalho
WORKDIR /app

# Copiar apenas requirements primeiro (melhor cache de Docker)
COPY requirements.txt .

# Instalar dependências
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código da aplicação
COPY ./app ./app

# Mudar para utilizador não-root
USER appuser

# Expor porta
EXPOSE 8000

# Comando de arranque
# Render injecta a variável PORT automaticamente
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
