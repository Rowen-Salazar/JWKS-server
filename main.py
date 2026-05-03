from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher
import base64
import json
import jwt
import datetime
import sqlite3
import os
import uuid

hostName = "localhost"
serverPort = 8080
DB_FILE = "totally_not_my_privateKeys.db" # Database filename

# --- Encryption Utilities ---

def get_master_key():
    """Retrieves the master AES key from the environment variable 'NOT_MY_KEY'."""
    key_b64 = os.getenv("NOT_MY_KEY")
    if not key_b64:
        raise EnvironmentError("CRITICAL: 'NOT_MY_KEY' environment variable is not set. Aborting.")
    # Decode the base64 key provided in the env
    return base64.b64decode(key_b64)

def encrypt_key(data_bytes):
    """Encrypts private key bytes using AES-GCM and returns a Base64 string."""
    aesgcm = AESGCM(get_master_key())
    nonce = os.urandom(12)  # Standard 12-byte GCM nonce
    ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
    # Store as nonce + ciphertext (auth tag is included in ciphertext in AESGCM)
    return base64.b64encode(nonce + ciphertext)

def decrypt_key(encrypted_b64):
    """Decrypts the Base64 encrypted payload back to original key bytes."""
    data = base64.b64decode(encrypted_b64)
    aesgcm = AESGCM(get_master_key())
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

# --- Database Initialization ---
ph = PasswordHasher(
    time_cost=3, 
    memory_cost=65536, 
    parallelism=4, 
    hash_len=32, 
    salt_len=16
)

def init_db():
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        #Keys table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        ''')
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP      
            )
        ''')
        # Auth table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,  
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()
        print("Database initialized successfully.")
    except sqlite3.Error as e:
        print(f"Error initializing database: {e}")
    finally:
        if conn:
            conn.close()

def save_key_to_db(key_pem, expires_at):
    conn = None
    try:
        encrypted_pem = encrypt_key(key_pem)
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_pem, expires_at))
        conn.commit()
        # Return the ID of the key we just saved
        return cursor.lastrowid
    except sqlite3.Error as e:
        print(f"Failed to insert key into database: {e}")
        return None
    finally:
        if conn:
            conn.close()

def register_user(username, password, email=None):
    """Hashes the password and saves the user to the database."""
    hashed_password = ph.hash(password)
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, email) 
            VALUES (?, ?, ?)
        ''', (username, hashed_password, email))
        conn.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        print("Error: Username or email already exists.")
        return None
    finally:
        conn.close()
        
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
numbers = private_key.private_numbers()

expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        path = parsed_path.path.rstrip('/')
        
        # --- New /register Endpoint ---
        if path == "/register":
            try:
                # 2. Parse the data we already read
                user_data = json.loads(post_data.decode('utf-8'))
                username = user_data.get("username")
                
                # 3. Generate password and hash
                generated_password = str(uuid.uuid4())
                password_hash = ph.hash(generated_password)
                
                # 4. Use a context manager for the DB to avoid hung locks
                with sqlite3.connect(DB_FILE) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                        (username, password_hash, user_data.get("email"))
                    )
                    conn.commit()

                # 5. Send response and RETURN
                self.send_response(201)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"password": generated_password}).encode('utf-8'))
                print(">>> Registration successful")
                return 

            except Exception as e:
                print(f">>> Registration Error: {e}")
                self.send_response(500)
                self.end_headers()
                return

        # Default 405 if no path matches
        self.send_response(405)
        self.end_headers()
        
        if path == "/auth":
            # Extract username from request body to find user_id
            user_id = None
            username = None
            if content_length > 0:
                try:
                    # username = post_data.get("username")
                    body = json.loads(post_data.decode('utf-8'))
                    username = body.get("username")
                    
                    # Look up user_id
                    conn = sqlite3.connect(DB_FILE)
                    cursor = conn.cursor()
                    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                    result = cursor.fetchone()
                    if result:
                        user_id = result[0]
                    else:
                        print("Auth attempt for non-exist user:")
                    # 2. Log the authentication request
                    cursor.execute('''
                        INSERT INTO auth_logs (request_ip, user_id) 
                        VALUES (?, ?)
                    ''', (self.client_address[0], user_id))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass # Log entry should ideally not crash the auth process

            # Existing JWT generation logic...
            headers = {"kid": "goodKID"}
            token_payload = {
                "user": "username",
                "exp": int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp())
            
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return
        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":

    # 1. Initialize the DB file and table
    init_db()
    
    # 2. Store the keys generated at startup (Example usage)
    future_exp = int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp())
    past_exp = int((datetime.datetime.now() - datetime.timedelta(hours=1)).timestamp())
    save_key_to_db(pem, future_exp)
    save_key_to_db(expired_pem, past_exp)

    webServer = HTTPServer((hostName, serverPort), MyServer)

    print(f"Server starting on {hostName}:{serverPort}")
    try:
        print("Server is now listening...")
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
