import psycopg2
from psycopg2.extras import RealDictCursor

# Database connection
def get_db_connection():
    return psycopg2.connect(
        dbname="zkp",
        user="postgres",
        password="123",
        host="localhost",
        cursor_factory=RealDictCursor
    )

    # Store public key y with username
def store_user(username, y):
     conn = get_db_connection()
     cur = conn.cursor()
     cur.execute("INSERT INTO users (username, public_key) VALUES (%s, %s)", (username, y))
     conn.commit()
     print("User registered successfully!")
     cur.close()
     conn.close()

 # Retrieve public key by username
def get_public_key(username):
     conn = get_db_connection()
     cur = conn.cursor()
     cur.execute("SELECT public_key FROM users WHERE username = %s", (username,))
     user = cur.fetchone()
     cur.close()
     conn.close()
     return user['public_key'] if user else None
