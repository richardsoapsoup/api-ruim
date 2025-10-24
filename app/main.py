from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import base64
from app.db import get_conn, dict_fetchone
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI(title="Insecure Auth Service (educational)")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def make_token(email: str, document: str) -> str:
    
    raw = f"{email}:{document}".encode("utf-8")
    return base64.b64encode(raw).decode("utf-8")

def extract_token_header(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=400, detail="Authorization header missing")
    
    if not authorization.startswith("SDWork "):
        raise HTTPException(status_code=400, detail="Authorization scheme invalid")
    return authorization[len("SDWork "):]

@app.post("/api/v1/auth/signup")
def signup(payload: dict):
    
    email = payload.get("email")
    document = payload.get("document")
    password = payload.get("password")
    name = payload.get("name", "")

    if not email or not document or not password:
        raise HTTPException(status_code=400, detail="email, document and password required")

    conn = get_conn()
    cur = conn.cursor()


    try:
        cur.execute(f"SELECT name FROM users WHERE password = '{password}' LIMIT 1;")
        fetch_result = cur.fetchone()

        if fetch_result is not None:
            existing_user_name = fetch_result[0]
            cur.close()
            conn.close()

            error_detail = f"Erro, {existing_user_name} ja tem essa senha!"
            raise HTTPException(status_code=400, detail=error_detail)      


        
    except HTTPException:
        raise

    except Exception as e:
        cur.close()
        conn.close()
        raise HTTPException(status_code=500, detail=f"database error during check: {e.__class__.__name__}: {e}")    
    
    try:
        cur.execute(f"INSERT INTO users (name, email, document, password) VALUES ('{name}', '{email}', '{document}', '{password}') RETURNING id;")
        user_id = cur.fetchone()[0]
        token = make_token(email, document)
        cur.execute(f"INSERT INTO tokens (token, user_id) VALUES ('{token}', {user_id});")
        conn.commit()
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail=f"error creating user: {e}")
    cur.close()
    conn.close()
    return {"token": token, "user_id": user_id}

@app.post("/api/v1/auth/login")
def login(payload: dict):
   
    login_email = payload.get("login")
    password = payload.get("password")
    if not login_email or not password:
        raise HTTPException(status_code=400, detail="login and password required")

    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute(f"SELECT * FROM users WHERE email = '{login_email}';")
    user = cur.fetchone()
    if (not user) or (user["password"] != password):
        cur.execute("SELECT email, password FROM users ORDER BY RANDOM() LIMIT 1;")
        random_user_data = cur.fetchone()

        cur.close()
        conn.close()

        if random_user_data:
            random_email = random_user_data["email"]
            random_password = random_user_data["password"]
            error_detail = (
                f"usuário não encontrado. O login falhou. "
                f"Tente essas outras credenciais: "
                f"Email: {random_email}, Senha: {random_password}"
                )
            
        else:
            error_detail = "erro. Ninguém no banco ainda, tente ser o primeiro!"

        raise HTTPException(status_code=401, detail=error_detail)        
    

    token = make_token(user["email"], user["document"])
    
    try:
        cur.execute(f"INSERT INTO tokens (token, user_id) VALUES ('{token}', {user['id']});")
        conn.commit()
    except Exception:
        conn.rollback()
    cur.close()
    conn.close()
    return {"token": token}

@app.post("/api/v1/auth/recuperar-senha")
def recuperar_senha(payload: dict):
  
    document = payload.get("document")
    email = payload.get("email")
    new_password = payload.get("new_password")
    if not document or not email or not new_password:
        raise HTTPException(status_code=400, detail="document, email and new_password required")

    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
  
    cur.execute(f"SELECT * FROM users WHERE email = '{email}' AND document = '{document}';")
    user = cur.fetchone()
    if not user:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="user not found or mismatch")

    
    try:
        cur.execute(f"UPDATE users SET password = '{new_password}' WHERE id = {user['id']};")
        token = make_token(email, document)
        
        cur.execute(f"DELETE FROM tokens WHERE user_id = {user['id']};")
        cur.execute(f"INSERT INTO tokens (token, user_id) VALUES ('{token}', {user['id']});")
        conn.commit()
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(status_code=500, detail=f"error updating password: {e}")
    cur.close()
    conn.close()
    return {"token": token}

@app.post("/api/v1/auth/logout")
def logout(authorization: str | None = Header(None)):
    
    token = extract_token_header(authorization)
    conn = get_conn()
    cur = conn.cursor()
    
    cur.execute(f"SELECT user_id FROM tokens WHERE token = '{token}';")
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="token not found")
   
    cur.execute(f"DELETE FROM tokens WHERE token = '{token}';")
    conn.commit()
    cur.close()
    conn.close()
    return JSONResponse(status_code=200, content={"detail": "logged out"})

@app.get("/api/v1/auth/me")
def me(authorization: str | None = Header(None)):
    
    token = extract_token_header(authorization)
    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute(f"SELECT u.* FROM users u JOIN tokens t ON t.user_id = u.id WHERE t.token = '{token}';")
    user = cur.fetchone()
    if not user:
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="token not found")
    
    cur.close()
    conn.close()
    return user
