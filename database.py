import sqlite3
import os
import bcrypt

from crypto import encrypt_data

USERS_DB_FILE='users.db'

def setup_users_database():
    conn = sqlite3.connect(USERS_DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_salt BLOB NOT NULL,
            encrypted_dek BLOB NOT NULL,
            vault_path TEXT NOT NULL,
            totp_secret TEXT NULL 
        )
    ''')
    conn.commit()
    conn.close()

def check_user(username):
    conn=sqlite3.connect(USERS_DB_FILE)
    cursor=conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()  # .fetchone() returnează un rând sau None

    conn.close()

    return user is not None

def create_user(username,salt,encrypted_dek,vault_path):
    os.makedirs(vault_path, exist_ok=True)

    try:
        conn=sqlite3.connect(USERS_DB_FILE)
        cursor=conn.cursor()
        sql = '''
        INSERT INTO users (username, password_salt, encrypted_dek, vault_path)
        VALUES (?, ?, ?, ?)
        '''
        data_to_insert=(username,salt,encrypted_dek,vault_path)
        cursor.execute(sql,data_to_insert)
        conn.commit()
        conn.close()

        print(f"User {username} has been created.")
        return True
    except sqlite3.IntegrityError:
        # Asta se întâmplă dacă userul există deja (datorită 'UNIQUE')
        print(f"Eroare: Numele de utilizator {username} este deja folosit.")
        return False
    except Exception as e:
        print(f"A apărut o eroare la crearea utilizatorului: {e}")
        return False

def get_login_data(username):
    conn = None
    try:
        conn = sqlite3.connect(USERS_DB_FILE)
        cursor = conn.cursor()
        # --- MODIFICAT: Selectăm și totp_secret ---
        cursor.execute("SELECT password_salt, encrypted_dek, vault_path, totp_secret FROM users WHERE username = ?", (username,))
        # ----------------------------------------
        user_data = cursor.fetchone()
        return user_data # (salt, dek_blob, path, totp_secret)
    except Exception as e:
        print(f"Eroare la get_login_data: {e}")
        return None
    finally:
        if conn:
            conn.close()


def update_user_credentials(username, new_salt, new_encrypted_dek_blob):
    conn = None
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        # --- EROAREA ERA AICI: Trebuie să fie 'password_salt' ---
        cursor.execute("UPDATE users SET password_salt = ?, encrypted_dek = ? WHERE username = ?",
                       (new_salt, new_encrypted_dek_blob, username))
        # --------------------------------------------------
        conn.commit()
        return True
    except Exception as e:
        print(f"EROARE REALĂ la actualizarea bazei de date: {e}")
        return False
    finally:
        if conn:
            conn.close()

def set_totp_secret(username, secret):
    """ Salvează sau șterge cheia secretă TOTP pentru un utilizator. """
    conn = None
    try:
        conn = sqlite3.connect(USERS_DB_FILE)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET totp_secret = ? WHERE username = ?", (secret, username))
        conn.commit()
        return True
    except Exception as e:
        print(f"EROARE la set_totp_secret: {e}")
        return False
    finally:
        if conn:
            conn.close()

def get_totp_secret(username):
    """ Preia cheia secretă TOTP a unui utilizator. """
    conn = None
    try:
        conn = sqlite3.connect(USERS_DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT totp_secret FROM users WHERE username = ?", (username,))
        data = cursor.fetchone()
        return data[0] if data else None # Returnează cheia sau None
    except Exception as e:
        print(f"EROARE la get_totp_secret: {e}")
        return None
    finally:
        if conn:
            conn.close()