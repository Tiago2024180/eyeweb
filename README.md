# 👁️ Eye Web — Breach Checker (PAP)

**Verificador de Fugas de Dados com Privacidade Total**

Sistema profissional de verificação de *data breaches* utilizando o modelo K-Anonymity.
O email do utilizador **nunca sai do browser** — apenas o prefixo do hash SHA-256 é enviado à API.

---

## 📁 Estrutura do Monorepo

```
eye-web-monorepo/
├── frontend/           # Next.js (Vercel)
│   ├── src/
│   │   ├── app/        # App Router do Next.js 14+
│   │   ├── components/ # Componentes React reutilizáveis
│   │   ├── lib/        # Utilitários (hashing, API calls)
│   │   └── styles/     # CSS migrado do design PHP
│   ├── public/         # Assets estáticos
│   └── package.json
│
├── backend/            # FastAPI (Render)
│   ├── app/
│   │   ├── main.py     # Ponto de entrada da API
│   │   ├── routers/    # Endpoints organizados
│   │   ├── services/   # Lógica de negócio
│   │   └── utils/      # Utilitários (cache, parquet reader)
│   ├── requirements.txt
│   └── Dockerfile
│
├── updater/            # Scripts de automação (GitHub Actions)
│   ├── updater.py      # Script principal
│   ├── config.py       # Configurações
│   ├── requirements.txt
│   └── data/           # Dados temporários (ignorado pelo git)
│
├── .github/
│   └── workflows/
│       └── update-dataset.yml  # Cron job semanal
│
└── docs/               # Documentação adicional
```

---

## 🚀 Quick Start

### 1. Updater (Fase 1)
```bash
cd updater
pip install -r requirements.txt
python updater.py
```

### 2. Backend (Fase 2)
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### 3. Frontend (Fase 3)
```bash
cd frontend
npm install
npm run dev
```

---

## 🔐 Variáveis de Ambiente

Criar ficheiro `.env` na raiz ou configurar no serviço de hosting:

```env
# Hugging Face (Updater + Backend)
HF_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxx
HF_DATASET_REPO=teu-username/eye-web-breaches

# Backend
ENVIRONMENT=production
```

---

## 📊 Arquitetura

```
[Browser] → hash SHA-256 → prefixo (5 chars) → [FastAPI] → [Hugging Face Parquet]
                                                    ↓
                                            Lista de candidatos
                                                    ↓
[Browser] ← compara hash completo localmente ← JSON response
```

**Privacidade garantida:** O servidor nunca conhece o email real.

---

## 💰 Custos

| Serviço | Custo |
|---------|-------|
| Vercel (Frontend) | €0 |
| Render (Backend) | €0 |
| Hugging Face (Data) | €0 |
| GitHub Actions | €0 |
| **Total** | **€0** |

---

## � Deployment (Fase 4)

### Pré-requisitos
- Conta no [GitHub](https://github.com)
- Conta no [Render](https://render.com)
- Conta no [Vercel](https://vercel.com)
- Dataset já carregado no Hugging Face ✅

### 1. GitHub — Criar Repositório

```bash
# Navegar para a pasta do monorepo
cd eye-web-monorepo

# Inicializar git (se ainda não feito)
git init

# Adicionar todos os ficheiros (exceto os do .gitignore)
git add .

# Commit inicial
git commit -m "🚀 Initial commit - Eye Web Monorepo"

# Adicionar remote (substitui pelo teu URL)
git remote add origin https://github.com/TEU-USERNAME/eye-web-monorepo.git

# Push para o GitHub
git push -u origin main
```

### 2. Render — Deploy do Backend

1. Vai a [render.com](https://render.com) → **Dashboard** → **New** → **Web Service**
2. Conecta a tua conta GitHub
3. Seleciona o repositório `eye-web-monorepo`
4. Configura:
   - **Name:** `eye-web-api`
   - **Region:** `Frankfurt (EU Central)`
   - **Branch:** `main`
   - **Root Directory:** `backend`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Em **Environment Variables**, adiciona:
   - `ENVIRONMENT` = `production`
   - `HF_DATASET_REPO` = `Samezinho/eye-web-breaches`
6. Clica **Create Web Service**
7. Guarda o URL gerado (ex: `https://eye-web-api.onrender.com`)

### 3. Vercel — Deploy do Frontend

1. Vai a [vercel.com](https://vercel.com) → **Add New** → **Project**
2. Importa o repositório `eye-web-monorepo`
3. Configura:
   - **Framework Preset:** `Next.js`
   - **Root Directory:** `frontend`
4. Em **Environment Variables**, adiciona:
   - `NEXT_PUBLIC_API_URL` = `https://eye-web-api.onrender.com` (o URL do Render)
5. Clica **Deploy**
6. Guarda o URL gerado (ex: `https://eye-web.vercel.app`)

### 4. GitHub Actions — Configurar Secrets

Para o workflow de atualização automática funcionar:

1. Vai ao teu repositório no GitHub → **Settings** → **Secrets and variables** → **Actions**
2. Adiciona os seguintes secrets:
   - `HF_TOKEN` = `(o teu token do Hugging Face)`
   - `HF_DATASET_REPO` = `Samezinho/eye-web-breaches`

---

## 🔗 URLs de Produção

Após o deploy, terás:

| Serviço | URL |
|---------|-----|
| Frontend | `https://eye-web.vercel.app` |
| Backend API | `https://eye-web-api.onrender.com` |
| API Docs | `https://eye-web-api.onrender.com/docs` |
| Dataset | `https://huggingface.co/datasets/Samezinho/eye-web-breaches` |

---

## �📄 Licença

Projeto académico para PAP (Prova de Aptidão Profissional).

