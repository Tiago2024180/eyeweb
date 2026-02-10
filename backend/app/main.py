"""
===========================================
Eye Web Backend — Main Application
===========================================

API FastAPI para verificação de fugas de dados (breaches).

Execução local:
    uvicorn app.main:app --reload

Documentação:
    - Swagger UI: http://localhost:8000/docs
    - ReDoc: http://localhost:8000/redoc
"""

import logging
import time
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import get_settings
from .models import HealthResponse, ErrorResponse
from .routers import breach_router
from .routers.password_router import router as password_router
from .routers.url_router import router as url_router
from .routers.auth_router import router as auth_router
from .routers.admin_router import router as admin_router
from .routers.chat_router import router as chat_router
from .routers.user_chat_router import router as user_chat_router
from .routers.traffic_router import router as traffic_router, visit_router
from .services.breach_service import get_breach_service
from .services.traffic_service import TrafficService

# ===========================================
# CONFIGURAÇÃO
# ===========================================

settings = get_settings()

# Configurar logging
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)


# ===========================================
# LIFECYCLE (STARTUP/SHUTDOWN)
# ===========================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gerencia o ciclo de vida da aplicação.
    
    - Startup: inicializa recursos
    - Shutdown: limpa recursos
    """
    # === STARTUP ===
    logger.info("="*50)
    logger.info("👁️  Eye Web API a iniciar...")
    logger.info("="*50)
    logger.info(f"Ambiente: {settings.ENVIRONMENT}")
    logger.info(f"Dataset: {settings.HF_DATASET_REPO}")
    logger.info(f"Cache: {settings.CACHE_MAX_SIZE} partições")
    
    # Pré-aquecer serviço (opcional)
    service = get_breach_service()
    
    # Inicializar monitor de tráfego
    ts = TrafficService.get()
    await ts.init()
    
    logger.info("✅ API pronta!")
    logger.info("="*50)
    
    yield  # Aplicação a correr
    
    # === SHUTDOWN ===
    logger.info("👁️  Eye Web API a encerrar...")
    
    # Fechar cliente HTTP do serviço
    await service.close()
    
    logger.info("✅ Recursos libertados. Até à próxima!")


# ===========================================
# CRIAÇÃO DA APLICAÇÃO
# ===========================================

app = FastAPI(
    title=settings.API_TITLE,
    description=settings.API_DESCRIPTION,
    version=settings.API_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)


# ===========================================
# MIDDLEWARES
# ===========================================

# CORS - permite requests do frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Middleware de tráfego (logging + defesa automática)
@app.middleware("http")
async def traffic_middleware(request: Request, call_next):
    """Intercepta requests para logging, deteção de ameaças e bloqueio de IPs."""
    # Obter IP real (Render/Vercel adicionam X-Forwarded-For)
    ip = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if not ip:
        ip = request.client.host if request.client else "unknown"

    path = request.url.path
    logger.info(f"📥 {request.method} {path} [{ip}]")

    # Verificar se IP está bloqueado
    ts = TrafficService.get()
    if ts.is_blocked(ip):
        logger.warning(f"🚫 IP bloqueado rejeitado: {ip}")
        return JSONResponse(
            status_code=403,
            content={"error": "Acesso bloqueado", "detail": "O teu IP foi bloqueado pelo sistema de defesa."}
        )

    start = time.time()
    response = await call_next(request)
    elapsed_ms = int((time.time() - start) * 1000)

    logger.info(f"📤 {request.method} {path} → {response.status_code} ({elapsed_ms}ms)")

    # Log de tráfego (fire-and-forget — não atrasa a resposta)
    if ts.should_log(path):
        asyncio.create_task(ts.safe_log_request(
            ip=ip, method=request.method, path=path,
            status_code=response.status_code,
            user_agent=request.headers.get("user-agent", ""),
            response_time_ms=elapsed_ms,
        ))

    return response


# ===========================================
# EXCEPTION HANDLERS
# ===========================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handler global para exceções não tratadas."""
    logger.error(f"Erro não tratado: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Erro interno do servidor",
            "detail": str(exc) if settings.DEBUG else None
        }
    )


# ===========================================
# ROUTERS
# ===========================================

# Incluir routers com prefixo da API
app.include_router(
    breach_router,
    prefix=settings.API_PREFIX
)

# Router de passwords (dataset separado)
app.include_router(
    password_router
)

# Router de URL Checker (novo!)
app.include_router(
    url_router,
    prefix=settings.API_PREFIX
)

# Router de Autenticação (verificação com código)
app.include_router(
    auth_router,
    prefix=settings.API_PREFIX
)

# Router de Admin (MFA TOTP)
app.include_router(
    admin_router,
    prefix="/api"
)

# Router de Chat Admin (mensagens + IA)
app.include_router(
    chat_router,
    prefix="/api"
)

# Router de Chat Público (EyeWeb Agent widget)
app.include_router(
    user_chat_router,
    prefix="/api"
)

# Router de Tráfego (Monitor de defesa)
app.include_router(
    traffic_router,
    prefix="/api"
)

# Router de Visitas (beacon do frontend para registar page views)
app.include_router(
    visit_router,
    prefix="/api"
)


# ===========================================
# ENDPOINTS RAIZ
# ===========================================

@app.get(
    "/",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Health Check",
    description="Verifica se a API está a funcionar."
)
async def root() -> HealthResponse:
    """
    Endpoint raiz / health check.
    
    Retorna informações básicas sobre a API.
    """
    return HealthResponse(
        status="healthy",
        version=settings.API_VERSION,
        dataset_repo=settings.HF_DATASET_REPO
    )


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Health Check (alternativo)"
)
async def health() -> HealthResponse:
    """Alias para o endpoint raiz."""
    return await root()


# ===========================================
# ENDPOINT DE DEBUG (apenas desenvolvimento)
# ===========================================

if settings.DEBUG:
    @app.get("/debug/config", tags=["Debug"])
    async def debug_config():
        """
        Retorna configuração atual (apenas em modo debug).
        NUNCA expor em produção!
        """
        return {
            "environment": settings.ENVIRONMENT,
            "debug": settings.DEBUG,
            "hf_dataset_repo": settings.HF_DATASET_REPO,
            "cache_max_size": settings.CACHE_MAX_SIZE,
            "cache_ttl": settings.CACHE_TTL_SECONDS,
            "cors_origins": settings.CORS_ORIGINS
        }
