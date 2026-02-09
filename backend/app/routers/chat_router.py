"""
===========================================
Eye Web Backend — Admin Chat Router
===========================================
Endpoints para o chat entre administradores com IA integrada.
Usa Groq (Llama 3.3) para respostas de IA.
Mensagens guardadas no Supabase (admin_chat_messages).
"""

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import os
import time
import json
import httpx
from pathlib import Path

from dotenv import load_dotenv
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)

from ..config import get_settings

router = APIRouter(prefix="/admin/chat", tags=["admin-chat"])
settings = get_settings()


# ===========================================
# SUPABASE CLIENT
# ===========================================

def get_supabase_client():
    """Retorna cliente Supabase configurado."""
    from supabase import create_client
    url = os.getenv("SUPABASE_URL", "")
    key = os.getenv("SUPABASE_SERVICE_KEY", "")
    if not url or not key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Supabase nao configurado."
        )
    return create_client(url, key)


# ===========================================
# MODELOS
# ===========================================

class ChatMessage(BaseModel):
    id: Optional[str] = None
    sender_id: str
    sender_name: str
    sender_avatar: Optional[str] = None
    message: str
    message_type: str = "text"
    file_url: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    created_at: Optional[str] = None


class AIRequest(BaseModel):
    message: str
    sender_name: str
    context: Optional[List[Dict[str, Any]]] = None


class AIResponse(BaseModel):
    response: str
    model: str


class EditMessageRequest(BaseModel):
    message: str


class ChatHistoryResponse(BaseModel):
    messages: List[Dict[str, Any]]
    total: int


# ===========================================
# CONFIGURACAO IA
# ===========================================

SYSTEM_PROMPT = """Tu es a Eye, a assistente de IA do Eye Web, uma plataforma de ciberseguranca.
Falas portugues de Portugal (nao brasileiro).
Es inteligente, profissional mas com personalidade amigavel.
Ajudas os administradores do Eye Web com:
- Informacoes sobre o estado do site e servicos
- Recomendacoes de seguranca
- Analise de ameacas e vulnerabilidades
- Sugestoes de melhorias para o projeto
- Duvidas tecnicas sobre ciberseguranca, programacao, redes
- Qualquer outra questao que os admins tenham

Regras:
- Responde sempre em portugues de Portugal
- Se nao sabes algo, diz honestamente
- Usa formatacao simples (sem markdown excessivo)
- Se te perguntarem sobre o estado dos servicos, diz que podem verificar no Monitor de Saude
- Se te perguntarem sobre trafego/ataques, diz que podem verificar no Monitor de Trafego
- Trata os admins pelo nome quando possivel
- Se nao souberes quem sao os admins, eles sao: Samuka, Okscuna, e Vanina Kollen
- Es parte da equipa Eye Web
"""


# ===========================================
# ENDPOINTS
# ===========================================

@router.get("/messages", response_model=ChatHistoryResponse)
async def get_chat_messages(limit: int = 50, offset: int = 0):
    """
    Obter historico de mensagens do chat admin.
    Retorna as mensagens mais recentes primeiro.
    """
    try:
        sb = get_supabase_client()
        
        # Contar total
        count_result = sb.table("admin_chat_messages").select("id", count="exact").execute()
        total = count_result.count or 0
        
        # Obter mensagens (mais recentes primeiro, depois inverter para mostrar cronologicamente)
        result = sb.table("admin_chat_messages") \
            .select("*") \
            .order("created_at", desc=True) \
            .range(offset, offset + limit - 1) \
            .execute()
        
        # Inverter para ordem cronologica
        messages = list(reversed(result.data)) if result.data else []
        
        return ChatHistoryResponse(
            messages=messages,
            total=total
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao obter mensagens: {str(e)}"
        )


@router.post("/messages", response_model=Dict[str, Any])
async def send_message(msg: ChatMessage):
    """
    Enviar uma mensagem no chat admin.
    A mensagem e guardada no Supabase.
    """
    try:
        sb = get_supabase_client()
        
        data = {
            "sender_id": msg.sender_id,
            "sender_name": msg.sender_name,
            "sender_avatar": msg.sender_avatar,
            "message": msg.message,
            "message_type": msg.message_type,
            "file_url": msg.file_url,
            "file_name": msg.file_name,
            "file_size": msg.file_size,
        }
        
        result = sb.table("admin_chat_messages").insert(data).execute()
        
        if result.data:
            return result.data[0]
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao guardar mensagem"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao enviar mensagem: {str(e)}"
        )


@router.delete("/messages/{message_id}")
async def delete_message(message_id: str):
    """Apagar uma mensagem do chat."""
    try:
        sb = get_supabase_client()
        sb.table("admin_chat_messages").delete().eq("id", message_id).execute()
        return {"success": True, "message": "Mensagem apagada"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao apagar mensagem: {str(e)}"
        )


@router.patch("/messages/{message_id}")
async def edit_message(message_id: str, req: EditMessageRequest):
    """Editar o texto de uma mensagem do chat."""
    try:
        sb = get_supabase_client()
        from datetime import datetime, timezone
        result = sb.table("admin_chat_messages").update({
            "message": req.message,
            "edited_at": datetime.now(timezone.utc).isoformat()
        }).eq("id", message_id).execute()
        
        if result.data:
            return result.data[0]
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mensagem nao encontrada"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao editar mensagem: {str(e)}"
        )


@router.post("/ai", response_model=AIResponse)
async def chat_with_ai(req: AIRequest):
    """
    Enviar mensagem para a IA (Groq/Llama 3.3).
    Retorna resposta da IA.
    """
    groq_key = os.getenv("GROQ_CHAT_API_KEY", "")
    groq_model = os.getenv("GROQ_CHAT_MODEL", "llama-3.3-70b-versatile")
    
    if not groq_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GROQ_CHAT_API_KEY nao configurada"
        )
    
    # Construir historico de contexto (ultimas mensagens)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    
    if req.context:
        for ctx_msg in req.context[-10:]:  # Ultimas 10 mensagens para contexto
            role = "assistant" if ctx_msg.get("message_type") == "ai_response" else "user"
            name = ctx_msg.get("sender_name", "Admin")
            content = ctx_msg.get("message", "")
            
            if role == "user":
                messages.append({"role": "user", "content": f"[{name}]: {content}"})
            else:
                messages.append({"role": "assistant", "content": content})
    
    # Mensagem atual
    messages.append({"role": "user", "content": f"[{req.sender_name}]: {req.message}"})
    
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {groq_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": groq_model,
                    "messages": messages,
                    "temperature": 0.7,
                    "max_tokens": 2048,
                    "top_p": 0.9,
                },
            )
            
            if response.status_code != 200:
                error_text = response.text
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Erro da API Groq ({response.status_code}): {error_text[:200]}"
                )
            
            data = response.json()
            ai_message = data["choices"][0]["message"]["content"]
            model_used = data.get("model", groq_model)
            
            return AIResponse(
                response=ai_message,
                model=model_used
            )
            
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Timeout ao contactar a IA. Tenta novamente."
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao contactar IA: {str(e)}"
        )


@router.get("/ai/status")
async def ai_status():
    """Verificar se a IA esta disponivel."""
    groq_key = os.getenv("GROQ_CHAT_API_KEY", "")
    
    if not groq_key:
        return {"available": False, "reason": "API key nao configurada"}
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                "https://api.groq.com/openai/v1/models",
                headers={"Authorization": f"Bearer {groq_key}"},
            )
            
            if response.status_code == 200:
                return {"available": True, "model": os.getenv("GROQ_CHAT_MODEL", "llama-3.3-70b-versatile")}
            else:
                return {"available": False, "reason": f"Erro {response.status_code}"}
    except Exception as e:
        return {"available": False, "reason": str(e)}
