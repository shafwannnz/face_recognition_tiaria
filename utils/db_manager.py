import sqlite3
import os
from werkzeug.security import generate_password_hash # Buat enkripsi password biar aman

DB_FOLDER = 'database'
DB_NAME = 'absensi.db'
DB_PATH = os.path.join(DB_FOLDER, DB_NAME) # Menggabungkan nama folder dan file menjadi satu path lengkap

def create_connection():
    if not os.path.exists(DB_FOLDER):
        os.makedirs(DB_FOLDER)
    conn = sqlite3.connect(DB_PATH)
    return conn

def init_db():
    conn = create_connection()
    if conn is not None:
        cursor = conn.cursor()
        
        # 1. Tabel Users (Update: tambah username & password)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'karyawan', 
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 2. Tabel Attendance (Sama kayak kemarin)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                date_str TEXT,
                time_str TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # --- SEEDING DATA (Buat Akun Default biar bisa Login Awal) ---
        # Kita buat 1 akun Admin & 1 akun Manajer otomatis biar lu gak bingung login pake apa
        
        # Cek dulu apakah admin sudah ada?
        cursor.execute("SELECT * FROM users WHERE username='admin'")
        if not cursor.fetchone():
            # Buat Admin (Pass: admin123)
            pass_admin = generate_password_hash("admin123")
            cursor.execute("INSERT INTO users (username, password, name, role) VALUES (?, ?, ?, ?)", 
                           ('admin', pass_admin, 'Administrator', 'admin'))
            print("👤 Akun ADMIN dibuat: (User: admin, Pass: admin123)") # user admin pw admin123

        # Cek Manajer
        cursor.execute("SELECT * FROM users WHERE username='manajer'")
        if not cursor.fetchone():
            # Buat Manajer (Pass: manajer123)
            pass_manajer = generate_password_hash("manajer123")
            cursor.execute("INSERT INTO users (username, password, name, role) VALUES (?, ?, ?, ?)", 
                           ('manajer', pass_manajer, 'Pak Manajer', 'manajer'))
            print("👤 Akun MANAJER dibuat: (User: manajer, Pass: manajer123)") # user manajer pw manajer123

        conn.commit()
        print(f"✅ Database & Akun Default siap di: {DB_PATH}")
        conn.close()

if __name__ == '__main__':
    init_db()