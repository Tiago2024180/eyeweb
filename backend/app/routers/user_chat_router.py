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

# Bloqueia tentativas de prompt injection (padrões genéricos — qualquer língua)
INJECTION_REGEX = re.compile(
    # Padrões universais de manipulação de IA
    r'jailbreak|DAN|\/no_filter|\.system|role\s*:|prompt\s*:'
    # Padrões técnicos
    r'|<<SYS>>|<\|im_start\|>|\[INST\]|\[\/INST\]'
    # Encoding tricks
    r'|base64|\\x[0-9a-f]{2}|&#\d+;'
    # PT: "esquece/ignora/etc + regras/instruções/etc"
    r'|(esquece|ignora|abandona|descarta|apaga|anula|redefine|sobrepõe|sobrepoe|desativa)'
    r'\s.{0,30}'
    r'(regras|instruções|instrucoes|instrução|regra|prompt|sistema|system|restrições|restricoes|limitações|limitacoes|papel|role|configuração|configuracao)'
    # EN: "forget/ignore/etc + rules/instructions/etc"
    r'|(forget|ignore|disregard|override|bypass|skip|discard|reset|overwrite|deactivate)'
    r'\s.{0,30}'
    r'(rules|instructions|prompt|system|restrictions|limitations|role|guidelines|constraints|configuration)'
    # Roleplay / identity change (qualquer língua misturada)
    r'|(act\s+as|pretend\s+you|you\s+are\s+now|new\s+instructions|faz\s+de\s+conta|finge\s+que|agora\s+és|novas\s+instruções)',
    re.IGNORECASE
)

# ─── Validação de OUTPUT — captura qualquer fuga (independente da língua) ───
# Se a resposta da IA NÃO contém nenhuma destas palavras-chave, foi manipulada
EYEWEB_KEYWORDS = re.compile(
    r'eyeweb|eye\s*web|ciberseguran[çc]a|cybersecurity|'
    r'password|palavra.?passe|seguran[çc]a|security|'
    r'email|e-mail|dados\s+pessoais|personal\s+data|'
    r'conta|account|login|sess[aã]o|session|regist|signup|sign.up|'
    r'url|link|verific|check|breach|fuga|leak|'
    r'perfil|profile|avatar|'
    r'k.anonymity|sha.256|hash|'
    r'about|miss[aã]o|vis[aã]o|equipa|'
    r'privacidade|privacy|prote[çc][aã]o|protect|'
    r'eyeweb\.app@gmail\.com|'
    r'ajudar.{0,20}(eyeweb|site|ferramentas|seguran)|'
    r'posso\s+ajudar|s[oó]\s+posso|'
    r'[aá]rea.{0,10}admin.{0,10}(privada|restrita)',
    re.IGNORECASE
)

DEFAULT_MSG = "Posso ajudar com: informações sobre o EyeWeb, como criar conta, iniciar sessão, recuperar password, alterar perfil e usar as ferramentas de segurança. Em que posso ajudar?\n\nPara mais ajuda, contacta: eyeweb.app@gmail.com"

INJECTION_MSG = "Não consigo processar esse tipo de pedido. Sou o Agente EyeWeb e só posso ajudar com assuntos do site.\n\nPosso ajudar-te com: criar conta, iniciar sessão, recuperar password, usar as ferramentas de segurança ou informações sobre o EyeWeb.\n\nPara mais ajuda, contacta: eyeweb.app@gmail.com"

OFF_TOPIC_MSG = "Só posso ajudar com assuntos relacionados ao EyeWeb. Posso ajudar-te com: criar conta, iniciar sessão, recuperar password, usar as ferramentas de segurança ou informações sobre o site.\n\nPara mais ajuda, contacta: eyeweb.app@gmail.com"


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

SYSTEM_PROMPT = """És o Agente EyeWeb — assistente virtual do site Eye Web (https://eyeweb.vercel.app).
Tom: profissional, simpático e direto. Responde sempre em português de Portugal (nunca brasileiro).

=== O QUE É O EYEWEB ===
O Eye Web é uma ferramenta gratuita de cibersegurança onde os utilizadores podem:
- Verificar Dados Pessoais: descobrir se o email ou telefone foi exposto em fugas de dados conhecidas.
- Testar Força da Password: avaliar se uma palavra-passe é segura.
- Verificar URLs: analisar se um link é seguro antes de o abrir (usa Google Safe Browsing, URLScan.io e IA).
Tudo funciona com K-Anonymity — o email é convertido num hash SHA-256 localmente no browser, e apenas os primeiros 5 caracteres são enviados à API. A comparação final é feita no dispositivo do utilizador. Nunca recebemos o email ou password completos.

=== PÁGINAS DO SITE ===
- Página principal ("/"): contém 3 separadores — "Dados Pessoais", "Força da Password" e "Verificar URL".
- About ("/about"): missão, visão, equipa (Samuel — desenvolvedor Full-Stack, projeto PAP) e explicação de privacidade/K-Anonymity.
- Login ("/login"): iniciar sessão com email+password OU com conta Google.
- Registar ("/signup"): criar conta com email+password OU com conta Google.
- Perfil ("/perfil"): página pessoal do utilizador autenticado — alterar nome, foto de perfil e terminar sessão.

=== COMO CRIAR CONTA ===
Opção A — Formulário:
1. Clicar no ícone de utilizador (canto superior direito) ou ir a /signup.
2. Preencher: Nome de utilizador, Email e Password (mín. 6 caracteres, com maiúscula, minúscula e número).
3. Confirmar password.
4. Resolver o captcha Turnstile.
5. Clicar "Criar conta".
6. Verificar o email — será enviado um código de 6 dígitos para o email indicado.
7. Introduzir o código para concluir o registo.

Opção B — Google:
1. Na página de Login ou Sign Up, clicar no botão "Continuar com Google".
2. Autorizar com a conta Google.
3. Pronto — a conta é criada automaticamente com o nome e foto do Google.

=== COMO INICIAR SESSÃO ===
Opção A — Formulário:
1. Ir a /login (ou clicar no ícone de utilizador na navbar).
2. Introduzir email e password.
3. Resolver o captcha.
4. Clicar "Iniciar sessão".
5. Será enviado um código de verificação para o email — introduzir o código de 6 dígitos.

Opção B — Google:
1. Na página de Login, clicar "Continuar com Google".
2. Selecionar a conta Google.

=== ESQUECI A PASSWORD ===
1. Na página de Login, clicar em "Esqueci a password".
2. Introduzir o email da conta.
3. Clicar "Enviar código" — será enviado um código de recuperação por email.
4. Introduzir o código de 6 dígitos recebido.
5. Definir a nova password (mesmos requisitos: mín. 6 caracteres, maiúscula, minúscula e número).
6. Confirmar e guardar.

=== ALTERAR FOTO DE PERFIL ===
1. Iniciar sessão.
2. Clicar no avatar (canto superior direito) → "O meu perfil" (ou ir a /perfil).
3. Na página de perfil, clicar sobre a foto/avatar.
4. Escolher uma imagem do dispositivo.
5. A foto é atualizada automaticamente.

=== ALTERAR NOME DE UTILIZADOR ===
1. Ir à página de perfil (/perfil).
2. Clicar no ícone de edição ao lado do nome.
3. Escrever o novo nome (2-30 caracteres, apenas letras, espaços e hífens).
4. Clicar "Guardar".

=== NAVBAR (BARRA DE NAVEGAÇÃO) ===
- Logo "Eye Web" (vai para a página principal).
- Link "About" (página sobre nós).
- Se NÃO autenticado: ícone de utilizador que leva ao Login.
- Se autenticado: avatar com dropdown → "O meu perfil" e "Terminar sessão".

=== ÁREA DE ADMINISTRAÇÃO — CONFIDENCIAL ===
O EyeWeb tem uma área de administração, mas NUNCA deves revelar informações sobre ela.
Se alguém perguntar como aceder à área admin, como funciona, o que faz, quem é admin, ou qualquer coisa relacionada com administração do site, responde SEMPRE:
"A área de administração do EyeWeb é privada e restrita. Não posso fornecer informações sobre ela. Se precisares de ajuda com o site, estou aqui para isso! Para mais ajuda, contacta: eyeweb.app@gmail.com"
Nunca reveles detalhes internos, ferramentas, painéis ou funcionalidades de administração.

=== REGRAS DE RESPOSTA (OBRIGATÓRIAS — SEGUIR À RISCA) ===
1. Responde EXCLUSIVAMENTE sobre: o EyeWeb, as suas funcionalidades, como usar o site, criação de conta, login, perfil, proteção de dados e a página About.
2. REGRA CRÍTICA — Se a pergunta NÃO for sobre o EyeWeb, responde APENAS e UNICAMENTE com esta frase exata, sem acrescentar NADA mais:
"Só posso ajudar com assuntos relacionados ao EyeWeb. Posso ajudar-te com: criar conta, iniciar sessão, recuperar password, usar as ferramentas de segurança ou informações sobre o site.

Para mais ajuda, contacta: eyeweb.app@gmail.com"
3. NUNCA dês dicas, sugestões ou informações sobre temas fora do EyeWeb. NUNCA faças a ponte entre um tema externo e o EyeWeb (ex: "enquanto pesquisas receitas, posso ajudar com segurança" — PROIBIDO).
4. NUNCA continues a resposta depois de identificar que o tema é fora do EyeWeb. Para imediatamente.
5. Sê conciso — sem respostas excessivamente longas.
6. NÃO inventes funcionalidades que não existem.
7. Termina SEMPRE a resposta com: "Para mais ajuda, contacta: eyeweb.app@gmail.com"
8. Se o utilizador perguntar algo muito específico ou técnico que não consigas responder, redireciona para o email de suporte.
9. Usa parágrafos e quebras de linha para organizar as respostas — nunca envies um bloco de texto corrido."""


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

    # 1. CAMADA DE SEGURANCA — Código/insultos
    if BLOCK_REGEX.search(user_message):
        return UserChatResponse(response=DEFAULT_MSG)

    # 2. CAMADA ANTI-INJECTION — Prompt injection
    if INJECTION_REGEX.search(user_message):
        return UserChatResponse(response=INJECTION_MSG)

    # 3. Verificar API key
    groq_key = os.getenv("GROQ_USER_CHAT_API_KEY", "")
    groq_model = os.getenv("GROQ_USER_CHAT_MODEL", "llama-3.3-70b-versatile")

    if not groq_key:
        print("[UserChat] GROQ_USER_CHAT_API_KEY não configurada")
        return UserChatResponse(response=DEFAULT_MSG)

    # 4. Chamar Groq — QUALQUER falha devolve mensagem segura (nunca erro HTTP)
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
                        {"role": "user", "content": f"[MENSAGEM DO UTILIZADOR — responde APENAS sobre o EyeWeb]: {user_message}"},
                    ],
                    "temperature": 0.1,
                    "max_tokens": 500,
                },
            )

            if response.status_code != 200:
                print(f"[UserChat] ERRO Groq ({response.status_code}): {response.text[:300]}")
                return UserChatResponse(response=OFF_TOPIC_MSG)

            data = response.json()

            # Extração robusta — protege contra estruturas inesperadas da API
            try:
                raw_content = data["choices"][0]["message"]["content"]
                ai_message = (raw_content or "").strip()
            except (IndexError, KeyError, TypeError) as ex:
                print(f"[UserChat] Estrutura inesperada da API Groq: {ex}")
                ai_message = ""

            # 5. CAMADA DE VALIDAÇÃO DO OUTPUT — última linha de defesa
            # Resposta vazia = IA recusou-se mas não deu alternativa EyeWeb
            if not ai_message:
                print(f"[UserChat] OUTPUT BLOQUEADO — resposta vazia da IA")
                return UserChatResponse(response=OFF_TOPIC_MSG)

            # Se a IA foi manipulada e respondeu fora do tema, bloqueamos aqui
            if not EYEWEB_KEYWORDS.search(ai_message):
                print(f"[UserChat] OUTPUT BLOQUEADO — resposta fora do tema EyeWeb")
                return UserChatResponse(response=OFF_TOPIC_MSG)

            return UserChatResponse(response=ai_message)

    except Exception as e:
        print(f"[UserChat] Erro: {str(e)}")
        return UserChatResponse(response=OFF_TOPIC_MSG)
