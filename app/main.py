from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from psycopg2.extras import RealDictCursor
from cryptography.fernet import Fernet, InvalidToken
from app.db import get_conn 
from functools import wraps
import secrets
import os
import redis
import json
import base64

FALLBACK_KEY = 'xG-n8u6mK7g1rZp0Q3eYcO2jD5wL4vH9I8aF7tB6R5oV4cT3sU2qP1sW0vU9T8p7O6n5m4l3k2j1i0h'
key_bytes = FALLBACK_KEY.encode()[:32].ljust(32, b'0')
encoded_key = base64.urlsafe_b64encode(key_bytes)



try:
    FERNET = Fernet(encoded_key)
except ValueError:
    raise RuntimeError("Chave Fernet inválida. Certifique-se de que tenha 32 bytes codificados em base64 URL-safe.")


PUBLIC_RATE_LIMIT = {"limit": 10, "period": 60} 
AUTH_THROTTLE_LIMIT = {"limit": 30, "period": 60} 


MAX_ATTEMPTS = 3
BLOCK_TIME_SECONDS = 600 
BLOCK_KEY_PREFIX = "login_block"
ATTEMPTS_KEY_PREFIX = "login_attempts"





REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))

try:
    REDIS_CLIENT = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=0,
        decode_responses=True,
        socket_connect_timeout=2,  
        socket_timeout=2
    )
    REDIS_CLIENT.ping()
    print(f"Conexão Redis estabelecida em {REDIS_HOST}:{REDIS_PORT}")
except redis.exceptions.ConnectionError:
    print(f"ERRO: Não foi possível conectar ao Redis em {REDIS_HOST}:{REDIS_PORT}. Usando MockRedis.")
    class MockRedis:
        def __init__(self): print("Mock Redis (não persistente)")
        def incr(self, key): return 1
        def get(self, key): return None
        def setex(self, key, time, value): pass
        def set(self, key, value, ex=None): pass
        def delete(self, *keys): pass
        def pipeline(self): return self
        def execute(self): return [1]
        def hset(self, key, mapping): pass
        def hgetall(self, key): return {}
        def expire(self, key, time): pass
    REDIS_CLIENT = MockRedis()




def rate_limit(limit: int, period: int):
   
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = kwargs.get('request')
            if not request:
                raise Exception("O decorator de Limite de Taxa requer 'request: Request' na assinatura da função.")

           
            client_ip = request.client.host
            key = f"rate_limit:{func.__name__}:{client_ip}"
            
            
            pipe = REDIS_CLIENT.pipeline()
            pipe.incr(key)
            pipe.expire(key, period)
            
            
            results = pipe.execute()
            count = results[0]
            
            if count > limit:
                
                raise HTTPException(
                    status_code=429,
                    detail=f"Limite de taxa excedido ({limit} requisições por {period}s). Tente novamente mais tarde.",
                    headers={"Retry-After": str(period)}
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator



def check_and_update_brute_force(email: str, success: bool = False):
    
    block_key = f"{BLOCK_KEY_PREFIX}:{email}"
    attempts_key = f"{ATTEMPTS_KEY_PREFIX}:{email}"
    
    
    if REDIS_CLIENT.get(block_key):
        remaining_ttl = REDIS_CLIENT.ttl(block_key)
        remaining_minutes = (remaining_ttl // 60) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Usuário bloqueado por muitas tentativas. Tente novamente em {remaining_minutes} minutos."
        )

    if success:
        
        REDIS_CLIENT.delete(attempts_key)
        return

    
    count = REDIS_CLIENT.incr(attempts_key)
    
    if count == 1:
        
        REDIS_CLIENT.expire(attempts_key, BLOCK_TIME_SECONDS)
        
    if count >= MAX_ATTEMPTS:
        
        REDIS_CLIENT.setex(block_key, BLOCK_TIME_SECONDS, "blocked")
        
        raise HTTPException(
            status_code=429,
            detail="Muitas tentativas inválidas. Usuário bloqueado por 10 minutos."
        )
    
    
    raise HTTPException(status_code=401, detail="Credenciais inválidas.")




def make_token(user_id: int) -> str:
    
    raw_data = str(user_id).encode()
    return FERNET.encrypt(raw_data).decode()

def decrypt_token(token: str) -> int:
    
    try:
        decrypted_bytes = FERNET.decrypt(token.encode(), ttl=None) 
        return int(decrypted_bytes.decode())
    except (InvalidToken, TypeError, ValueError) as e:
        
        print(f"Falha na descriptografia do token: {e}")
        raise HTTPException(status_code=401, detail="Token inválido ou não autorizado.")

def extract_token_header(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Cabeçalho de Autorização ausente ou inválido.")
    
    if not authorization.startswith("SDWork "):
        raise HTTPException(status_code=401, detail="Esquema de Autorização inválido. Deve usar 'SDWork [TOKEN]'.")
    return authorization[len("SDWork "):]



app = FastAPI(title="Serviço de Autenticação Seguro")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



@app.post("/api/v1/auth/signup")
@rate_limit(**PUBLIC_RATE_LIMIT)
async def signup(payload: dict, request: Request):
   
    email = payload.get("email")
    document = payload.get("document")
    password = payload.get("password")
    name = payload.get("name", "")

    if not email or not document or not password:
        raise HTTPException(status_code=400, detail="email, document e password são obrigatórios")

    conn = get_conn()
    cur = conn.cursor()

    try:
        
        cur.execute("SELECT name FROM users WHERE password = %s LIMIT 1;", (password,))
        fetch_result = cur.fetchone()

        if fetch_result is not None:
            existing_user_name = fetch_result[0]
            cur.close()
            conn.close()

            error_detail = f"Erro, {existing_user_name} já tem essa senha!"
            raise HTTPException(status_code=400, detail=error_detail)
        
        
        cur.execute(
            "INSERT INTO users (name, email, document, password) VALUES (%s, %s, %s, %s) RETURNING id;", 
            (name, email, document, password)
        )
        user_id = cur.fetchone()[0]
        
        token = make_token(user_id) 
        
        
        cur.execute("INSERT INTO tokens (token, user_id) VALUES (%s, %s);", (token, user_id))
        conn.commit()
    
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=f"erro ao criar usuário: {e.__class__.__name__}: {e}")
    finally:
        cur.close()
        conn.close()
    
    return {"token": token, "user_id": user_id}

@app.post("/api/v1/auth/login")
@rate_limit(**PUBLIC_RATE_LIMIT)
async def login(payload: dict, request: Request):
    
    login_email = payload.get("login")
    password = payload.get("password")

    if not login_email or not password:
        raise HTTPException(status_code=400, detail="login e password são obrigatórios")

    
    try:
        check_and_update_brute_force(login_email)
    except HTTPException as e:
        if e.status_code == 401: 
            pass 
        else: 
            raise e
        
    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    
    cur.execute("SELECT id, email, document, password FROM users WHERE email = %s;", (login_email,))
    user = cur.fetchone()

    
    if (not user) or (user["password"] != password):
        
        check_and_update_brute_force(login_email, success=False)
        return

    
    check_and_update_brute_force(login_email, success=True)
    
    token = make_token(user["id"])

    try:
        
        cur.execute("INSERT INTO tokens (token, user_id) VALUES (%s, %s);", (token, user["id"]))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()

    return {"token": token}




@app.post("/api/v1/auth/request-password-reset")
@rate_limit(limit=3, period=300) 
async def request_password_reset(payload: dict, request: Request):
    
    document = payload.get("document")
    email = payload.get("email")

    if not document or not email:
        raise HTTPException(status_code=400, detail="document e email são obrigatórios")

    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    
    cur.execute("SELECT id FROM users WHERE email = %s AND document = %s;", (email, document))
    user = cur.fetchone()
    cur.close()
    conn.close()
    
    if not user:
        
        return JSONResponse(status_code=202, content={"detail": "Se os detalhes estiverem corretos, um código de redefinição foi 'enviado'."})

   
    reset_code = secrets.token_hex(3) 
    
    
    cache_key = f"reset_code:{email}"
    reset_data = {"user_id": user['id'], "code": reset_code}
    
    REDIS_CLIENT.setex(cache_key, 300, json.dumps(reset_data))

    
    return {"detail": "Código de redefinição de senha gerado e disponível no cache simulado.", "reset_code_for_demo": reset_code}

@app.post("/api/v1/auth/reset-password")
@rate_limit(limit=3, period=60) 
async def reset_password(payload: dict, request: Request):
    
    email = payload.get("email")
    reset_code = payload.get("reset_code")
    new_password = payload.get("new_password")

    if not email or not reset_code or not new_password:
        raise HTTPException(status_code=400, detail="email, reset_code e new_password são obrigatórios")

    
    cache_key = f"reset_code:{email}"
    cached_data_json = REDIS_CLIENT.get(cache_key)

    if not cached_data_json:
        raise HTTPException(status_code=401, detail="Código de redefinição inválido ou expirado.")

    try:
        cached_data = json.loads(cached_data_json)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Erro interno na validação do código.")

    if cached_data.get("code") != reset_code:
        raise HTTPException(status_code=401, detail="Código de redefinição inválido ou expirado.")
    
    user_id = cached_data["user_id"]

    conn = get_conn()
    cur = conn.cursor()
    
    try:
        
        cur.execute("UPDATE users SET password = %s WHERE id = %s;", (new_password, user_id))
        
        
        cur.execute("DELETE FROM tokens WHERE user_id = %s;", (user_id,))
        token = make_token(user_id)
        cur.execute("INSERT INTO tokens (token, user_id) VALUES (%s, %s);", (token, user_id))
        
        conn.commit()
        REDIS_CLIENT.delete(cache_key) 
        
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"erro ao atualizar senha: {e.__class__.__name__}: {e}")
    finally:
        cur.close()
        conn.close()
        
    return {"detail": "Senha atualizada com sucesso.", "token": token}


@app.post("/api/v1/auth/logout")
def logout(authorization: str | None = Header(None)):
    
    token = extract_token_header(authorization)
    
    
    try:
        decrypt_token(token)
    except HTTPException:
        pass 

    conn = get_conn()
    cur = conn.cursor()
    
   
    cur.execute("SELECT user_id FROM tokens WHERE token = %s;", (token,))
    row = cur.fetchone()
    
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Token não encontrado ou sessão já encerrada.")
        
    cur.execute("DELETE FROM tokens WHERE token = %s;", (token,))
    conn.commit()
    cur.close()
    conn.close()
    
    return JSONResponse(status_code=200, content={"detail": "Logout realizado com sucesso"})

@app.get("/api/v1/auth/me")
def me(authorization: str | None = Header(None)):
   
    token = extract_token_header(authorization)
    
    
    user_id = decrypt_token(token)
    
   
    key = f"auth_throttle:me:{user_id}"
    limit = AUTH_THROTTLE_LIMIT["limit"]
    period = AUTH_THROTTLE_LIMIT["period"]
    
   
    pipe = REDIS_CLIENT.pipeline()
    pipe.incr(key)
    pipe.expire(key, period)
    
    results = pipe.execute()
    count = results[0]
    
    if count > limit:
        raise HTTPException(
            status_code=429,
            detail=f"Limite de Throttling excedido ({limit} requisições por {period}s para o ID do usuário {user_id})."
        )
    
   
    
    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
   
    cur.execute("SELECT u.* FROM users u JOIN tokens t ON t.user_id = u.id WHERE t.token = %s;", (token,))
    user = cur.fetchone()
    
    if not user:
        cur.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Sessão expirada ou token revogado.")
    
    cur.close()
    conn.close()
    
   
    if 'password' in user:
        del user['password']
        
    return user