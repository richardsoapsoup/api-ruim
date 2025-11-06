import redis
from app.db import get_conn

print("Testando Redis...")
r = redis.Redis(host="localhost", port=6379)
r.ping()
print("Redis OK!")

print("Testando PostgreSQL...")
conn = get_conn()
cur = conn.cursor()
cur.execute("SELECT 1;")
print("PostgreSQL OK!")
cur.close()
conn.close()
