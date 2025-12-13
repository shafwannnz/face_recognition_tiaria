from flask import Flask, render_template, Response, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from flask import make_response
from fpdf import FPDF 
import cv2
import face_recognition
import pickle
import numpy as np
import os
from datetime import datetime
from utils.db_manager import create_connection
from models import User

app = Flask(__name__)
app.secret_key = "rahasia_super_aman"

# --- SETUP FLASK LOGIN ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

# --- KONFIGURASI AI ---
ENCODINGS_PATH = 'utils/encoding.pickle'
try:
    data = pickle.loads(open(ENCODINGS_PATH, "rb").read())
    known_encodings = data["encodings"]
    known_names = data["names"]
except:
    known_encodings = []
    known_names = []

# --- SETTING KAMERA (SOLUSI ANTI LAG 1) ---
camera = cv2.VideoCapture(0)
# Paksa resolusi kecil biar ringan (640x480 standard webcam)
camera.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

def mark_attendance(name, user_login):
    """ Mencatat absensi ke DB """
    conn = create_connection()
    if conn is not None:
        cursor = conn.cursor()
        now = datetime.now()
        date_str = now.strftime("%Y-%m-%d")
        time_str = now.strftime("%H:%M:%S")
        
        cursor.execute("SELECT id FROM users WHERE name=?", (name,))
        user_db = cursor.fetchone()
        
        if user_db:
            user_id = user_db[0]
            # Validasi: Pastikan wajah sama dengan akun yang login
            if user_login.is_authenticated and user_login.name == name:
                cursor.execute("SELECT * FROM attendance WHERE user_id=? AND date_str=?", (user_id, date_str))
                if not cursor.fetchone():
                    cursor.execute("INSERT INTO attendance (user_id, date_str, time_str) VALUES (?, ?, ?)", 
                                (user_id, date_str, time_str))
                    conn.commit()
                    print(f"✅ {name} Absen jam {time_str}")
            else:
                pass
        conn.close()

# --- FUNGSI GENERATOR (SOLUSI FIX ERROR + ANTI LAG 2) ---
def generate_frames(active_user):
    """ 
    Menerima parameter 'active_user' supaya tidak error NoneType.
    """
    frame_count = 0
    process_every_n_frames = 15 # Skip frame (Proses 1 frame, lewati 4)

    last_face_locations = []
    last_face_names = []

    while True:
        success, frame = camera.read()
        if not success:
            break
        else:
            frame_count += 1

            # --- LOGIKA SKIP FRAME (BIAR RINGAN) ---
            if frame_count % process_every_n_frames == 0:
                small_frame = cv2.resize(frame, (0, 0), fx=0.25, fy=0.25)
                rgb_small_frame = cv2.cvtColor(small_frame, cv2.COLOR_BGR2RGB)
                
                last_face_locations = face_recognition.face_locations(rgb_small_frame)
                face_encodings = face_recognition.face_encodings(rgb_small_frame, last_face_locations)
                
                last_face_names = []
                for face_encoding in face_encodings:
                    matches = face_recognition.compare_faces(known_encodings, face_encoding)
                    name = "Unknown"
                    face_distances = face_recognition.face_distance(known_encodings, face_encoding)
                    
                    if len(face_distances) > 0:
                        best_match_index = np.argmin(face_distances)
                        if matches[best_match_index]:
                            name = known_names[best_match_index]
                            
                            # Cek active_user ada isinya gak?
                            if active_user and active_user.is_authenticated:
                                mark_attendance(name, active_user)

                    last_face_names.append(name)

            # --- GAMBAR KOTAK ---
            for (top, right, bottom, left), name in zip(last_face_locations, last_face_names):
                top *= 4; right *= 4; bottom *= 4; left *= 4
                
                color = (0, 255, 0) # Default Hijau
                
                # Cek active_user dulu sebelum nanya is_authenticated
                if active_user and active_user.is_authenticated:
                    if name != active_user.name:
                        color = (0, 0, 255) # Merah (Salah Akun)
                
                cv2.rectangle(frame, (left, top), (right, bottom), color, 2)
                cv2.rectangle(frame, (left, bottom - 35), (right, bottom), color, cv2.FILLED)
                cv2.putText(frame, name, (left + 6, bottom - 6), cv2.FONT_HERSHEY_DUPLEX, 1.0, (255, 255, 255), 1)

            # Turunkan kualitas JPG ke 60%
            ret, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 60])
            frame_bytes = buffer.tobytes()
            yield (b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

# --- ROUTES (JALUR WEB) ---

@app.route('/')
def root():
    """ 
    Route Pintu Utama (Gatekeeper).
    Logic: Cek session. Kalau belum login -> Login. Kalau udah -> Dashboard.
    """
    if current_user.is_authenticated:
        # Kalau user memaksakan buka halaman utama padahal udah login,
        # Arahkan kembali ke dashboard sesuai role mereka.
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'manajer':
            return redirect(url_for('manajer_dashboard'))
        else:
            return redirect(url_for('karyawan_absensi'))
    else:
        # Kalau belum login, paksa ke halaman login
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Proteksi: Kalau sudah login, tendang balik ke root
    if current_user.is_authenticated:
        return redirect(url_for('root'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = User.get_by_username(username)
        
        if user_data and check_password_hash(user_data[2], password):
            user = User(id=user_data[0], username=user_data[1], name=user_data[3], role=user_data[4])
            login_user(user)
            # Redirect ke root biar dipilah sama Gatekeeper
            return redirect(url_for('root')) 
        else:
            flash('Login Gagal. Cek username/password.')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Anda berhasil logout.', 'success')
    return redirect(url_for('login'))

# --- HALAMAN KARYAWAN (Dulu Index, Sekarang /absensi) ---
@app.route('/absensi')
@login_required
def karyawan_absensi():
    return render_template('index.html', user=current_user)

@app.route('/video_feed')
@login_required
def video_feed():
    # Fix Error NoneType: Kirim current_user ke fungsi generator
    return Response(generate_frames(current_user), mimetype='multipart/x-mixed-replace; boundary=frame')

# --- HALAMAN ADMIN ---
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin': return "⛔ AKSES DITOLAK"
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users ORDER BY id DESC")
    all_users = cursor.fetchall()
    conn.close()
    return render_template('admin_dashboard.html', users=all_users)

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin': return redirect(url_for('root')) # Redirect ke root kalau bukan admin
    name = request.form['name']
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    hashed_password = generate_password_hash(password)
    
    conn = create_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (name, username, password, role) VALUES (?, ?, ?, ?)", 
                       (name, username, hashed_password, role))
        conn.commit()
        flash('✅ User berhasil ditambahkan!', 'success')
    except Exception as e:
        flash(f'❌ Gagal: {e}', 'error')
    finally:
        conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin': return redirect(url_for('root'))
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    flash('🗑️ User dihapus.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- HALAMAN MANAJER ---
@app.route('/manajer')
@login_required
def manajer_dashboard():
    if current_user.role != 'manajer': return "⛔ AKSES DITOLAK"
    return f"<h1>Halaman Manajer</h1><p>Halo {current_user.name}.</p><a href='/logout'>Logout</a>"

if __name__ == '__main__':
    app.run(debug=True)