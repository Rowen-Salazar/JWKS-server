DB_FILE = "totally_not_my_privateKeys.db" # Database filename

# --- Database Initialization ---
def init_db():
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        ''')
        conn.commit()
        print("Database initialized successfully.")
    except sqlite3.Error as e:
        print(f"Error initializing database: {e}")
    finally:
        if conn:
            conn.close()
    # conn = sqlite3.connect(DB_FILE)
    # cursor = conn.cursor()
    # Create the keys table if it doesn't exist
    # cursor.execute('''
        # CREATE TABLE IF NOT EXISTS keys(
            # kid INTEGER PRIMARY KEY AUTOINCREMENT,
            # key BLOB NOT NULL,
            # exp INTEGER NOT NULL
        # )
    # ''')
    # conn.commit()
    # conn.close()

def save_key_to_db(key_pem, expires_at):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key_pem, expires_at))
            # conn.commit() is called automatically if no error occurs
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    # conn = sqlite3.connect(DB_FILE)
    # cursor = conn.cursor()
    # cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key_pem, expires_at))
    # conn.commit()
    # conn.close()

def get_key(expired=False):
    """Fetches a key from the database based on expiration status."""
    import datetime
    current_time = int(datetime.datetime.now().timestamp())
    
    try:
        with closing(sqlite3.connect(DB_FILE)) as conn:
            cursor = conn.cursor()
            if expired:
                cursor.execute("SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1", (current_time,))
            else:
                cursor.execute("SELECT kid, key FROM keys WHERE exp > ? LIMIT 1", (current_time,))
            return cursor.fetchone() # Returns (kid, key_blob) or None
    except sqlite3.Error as e:
        print(f"Error retrieving key: {e}")
        return None
