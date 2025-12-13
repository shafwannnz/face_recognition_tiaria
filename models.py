from flask_login import UserMixin
from utils.db_manager import create_connection

class User(UserMixin):
    def __init__(self, id, username, name, role):
        self.id = id
        self.username = username
        self.name = name
        self.role = role

    @staticmethod
    def get_by_username(username):
        """ Cari user di database berdasarkan username """
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            # Urutan kolom di DB: id, username, password, name, role
            return user_data # Balikin data mentah (tuple)
        return None

    @staticmethod
    def get_by_id(user_id):
        """ Cari user berdasarkan ID (dipakai Flask-Login buat ngenalin session) """
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            # Kita buat objek User biar enak dipakai di app.py
            return User(id=user_data[0], username=user_data[1], name=user_data[3], role=user_data[4])
        return None