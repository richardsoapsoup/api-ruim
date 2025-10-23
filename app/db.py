

import psycopg2
from psycopg2.extras import RealDictCursor


def get_conn():
    conn = psycopg2.connect(
        host="localhost",       
        port=5432,
        dbname="auth_db",
        user="postgres",
        password="123",   
        client_encoding="UTF8"  
    )
    return conn


def dict_fetchone(cursor):    
    row = cursor.fetchone()
    return dict(row) if row else None
