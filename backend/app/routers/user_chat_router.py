"""
===========================================
Eye Web Backend — User Chat Router
===========================================
Endpoint para o chatbot público (widget EyeWeb Agent).
Usa Groq (Llama 3.3) com API key separada.
Focado em: EyeWeb, proteção de dados, subscrição.
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
import os
import re
import httpx

from pathlib import Path
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)


router = APIRouter(prefix="/user/chat", tags=["user-chat"])


# ===========================================
# SEGURANCA
# ===========================================

# Bloqueia código (HTML/JS/SQL) e insultos comuns
BLOCK_REGEX = re.compile(
    r'<[^>]*>|'
    r'(\b(script|function|alert|console|window|document|select\s+\*|drop\s+table|insert\s+into|delete\s+from|'
    r'merda|porra|caralho|idiota|stupid|fuck|shit)\b)|'
    r'([{}[\];])',
    re.IGNORECASE
)

DEFAULT_MSG = "Posso ajudar apenas com: Informação sobre o EyeWeb, Proteção de Dados e Subscrição ao EyeWeb. Como posso ser útil?"


# ===========================================
# MODELOS
# ===========================================

class UserChatRequest(BaseModel):
    message: str


class UserChatResponse(BaseModel):
    response: str


# ===========================================
# SYSTEM PROMPT
# ===========================================

SYSTEM_PROMPT = """És o Agente EyeWeb. O teu tom é profissional e direto. O EyeWeb trata-se de um site onde os utilizadores podem verificar se as suas informações foram vazadas (palavras-passe ou números de telefone), além de verificar se URLs são seguros de aceder. 

Responde apenas sobre: Informação sobre o EyeWeb (o que é, como usar, como funciona, etc), Proteção de Dados e Subscrição ao EyeWeb. 

Regras: 
1) Sem explicações muito técnicas nem longas, mas com coerência.
2) Se o assunto for outro, houver algum insulto ou existir inserção de código, responde apenas com os tópicos que abordas.
3) Restringir as respostas aos tópicos que abordas.
4) Responde sempre em português de Portugal (não brasileiro)."""


# ===========================================
# ENDPOINT
# ===========================================

@router.post("", response_model=UserChatResponse)
async def user_chat(req: UserChatRequest):
    """
    Chat público do EyeWeb Agent.
    Responde apenas sobre EyeWeb, proteção de dados e subscrição.
    """
    user_message = (req.message or "").strip()

    if not user_message:
        return UserChatResponse(response=DEFAULT_MSG)

    # 1. CAMADA DE SEGURANCA (antes de chamar a IA)
    if BLOCK_REGEX.search(user_message):
        return UserChatResponse(response=DEFAULT_MSG)

    # 2. Verificar API key
    groq_key = os.getenv("GROQ_USER_CHAT_API_KEY", "")
    groq_model = os.getenv("GROQ_USER_CHAT_MODEL", "llama-3.3-70b-versatile")

    if not groq_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GROQ_USER_CHAT_API_KEY não configurada"
        )

    # 3. Chamar Groq
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {groq_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": groq_model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_message},
                    ],
                    "temperature": 0.3,
                    "max_tokens": 350,
                },
            )

            if response.status_code != 200:
                error_text = response.text
                print(f"[UserChat] ERRO Groq ({response.status_code}): {error_text[:300]}")
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Erro da API Groq ({response.status_code})"
                )

            data = response.json()
            ai_message = data["choices"][0]["message"]["content"]

            return UserChatResponse(response=ai_message)

    except httpx.TimeoutException:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Timeout ao contactar a IA. Tenta novamente."
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"[UserChat] Erro: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno."
        )
