from flask import Flask, render_template, Response, request, redirect, url_for, flash, send_file, session # <-- Tambah session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import cv2
import face_recognition
import pickle
import numpy as np
import os
import pandas as pd
from datetime import datetime, timedelta # <-- Tambah timedelta
from io import BytesIO
from fpdf import FPDF
from utils.db_manager import create_connection
from models import User

app = Flask(__name__)
app.secret_key = "rahasia_super_aman"

# --- UPDATE KEAMANAN: AUTO LOGOUT 1 MENIT ---
# Kalau user tidak ngapa-ngapain selama 1 menit, sesi hangus.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)

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

# # --- SETTING KAMERA ---
# camera = cv2.VideoCapture(0)
# camera.set(cv2.CAP_PROP_FRAME_WIDTH, 1080) # Ubah ke 1:1 ya ges ya
# camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 1080)

def mark_attendance(name, user_login):
    """ Mencatat absensi & Nulis ke file log.txt biar kebaca """
    
    # Buka file log.txt (Mode Append)
    with open("log.txt", "a") as f:
        f.write(f"\n[{datetime.now()}] SCAN DETECTED: {name}\n")
    
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
            # Validasi Nama
            if user_login.is_authenticated and user_login.name == name:
                
                # Cek Spam (2 menit)
                cursor.execute("SELECT time_str FROM attendance WHERE user_id=? AND date_str=? ORDER BY id DESC LIMIT 1", (user_id, date_str))
                last_attendance = cursor.fetchone()
                
                should_record = False
                if not last_attendance:
                    should_record = True
                    with open("log.txt", "a") as f: f.write(f"   -> Status: Absen PERTAMA hari ini. REKAM!\n")
                else:
                    last_time = datetime.strptime(last_attendance[0], "%H:%M:%S")
                    current_time = datetime.strptime(time_str, "%H:%M:%S")
                    diff = (current_time - last_time).total_seconds()
                    
                    if diff > 120:
                        should_record = True
                        with open("log.txt", "a") as f: f.write(f"   -> Status: Absen PULANG (Face Out). Selisih {diff}s\n")
                    else:
                        with open("log.txt", "a") as f: f.write(f"   -> SPAM: Ditolak, baru {diff}s lalu.\n")

                if should_record:
                    cursor.execute("INSERT INTO attendance (user_id, date_str, time_str) VALUES (?, ?, ?)", (user_id, date_str, time_str))
                    conn.commit()
                    print(f"✅ DATA MASUK: {name}") # Tetap print ke terminal
            else:
                with open("log.txt", "a") as f: f.write(f"   -> ERROR: Wajah ({name}) != Akun ({user_login.name})\n")
        
        conn.close()

def generate_frames(active_user):
    print("📸 Mencoba menyalakan kamera...")
    
    # TAMBAHAN: cv2.CAP_DSHOW (Biar di Windows sat-set nyalanya)
    camera = cv2.VideoCapture(0, cv2.CAP_DSHOW)
    
    # Setting resolusi biar gambar gak pecah
    camera.set(cv2.CAP_PROP_FRAME_WIDTH, 1080)
    camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 1080)
    
    if not camera.isOpened():
        print("❌ GAGAL: Kamera tidak terdeteksi atau dikunci aplikasi lain!")
        return

    frame_count = 0
    process_every_n_frames = 15
    last_face_locations = []
    last_face_names = []
    
    debug_status = "Menunggu Wajah..." 
    debug_color = (255, 255, 255) 

    try:
        while True:
            success, frame = camera.read()
            if not success:
                print("⚠️ Warning: Gagal membaca frame kamera.")
                break
            else:
                frame_count += 1
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
                                
                                if active_user and active_user.is_authenticated:
                                    if active_user.name == name:
                                        mark_attendance(name, active_user)
                                        debug_status = f"SUKSES: Data {name} Masuk!"
                                        debug_color = (0, 255, 0)
                                    else:
                                        debug_status = f"GAGAL: Login '{active_user.name}' != Wajah '{name}'"
                                        debug_color = (0, 0, 255)
                                else:
                                    debug_status = "ERROR: User dianggap belum login!"
                                    debug_color = (0, 255, 255)

                        last_face_names.append(name)

                for (top, right, bottom, left), name in zip(last_face_locations, last_face_names):
                    top *= 4; right *= 4; bottom *= 4; left *= 4
                    cv2.rectangle(frame, (left, top), (right, bottom), debug_color, 2)
                    cv2.rectangle(frame, (left, bottom - 35), (right, bottom), debug_color, cv2.FILLED)
                    cv2.putText(frame, name, (left + 6, bottom - 6), cv2.FONT_HERSHEY_DUPLEX, 1.0, (255, 255, 255), 1)

                cv2.putText(frame, debug_status, (10, 470), cv2.FONT_HERSHEY_SIMPLEX, 0.7, debug_color, 2)

                ret, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 60])
                frame_bytes = buffer.tobytes()
                yield (b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

    except Exception as e:
        print(f"Error Camera Loop: {e}")
        
    finally:
        camera.release()
        print("📸 Kamera dimatikan (Resource Released).")

# --- ROUTES ---

# Tambahkan ini biar tiap request sesi diperbarui waktunya
@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5) # Logout otomatis setelah 5 menit idle

@app.route('/')
def root():
    if current_user.is_authenticated:
        if current_user.role == 'admin': return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'manajer': return redirect(url_for('manajer_dashboard'))
        else: return redirect(url_for('karyawan_absensi'))
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('root'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_data = User.get_by_username(username)
        
        if user_data and check_password_hash(user_data[2], password):
            user = User(id=user_data[0], username=user_data[1], name=user_data[3], role=user_data[4])
            login_user(user)
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

# --- HALAMAN KARYAWAN ---
@app.route('/absensi')
@login_required
def karyawan_absensi():
    return render_template('index.html', user=current_user)

@app.route('/video_feed')
@login_required
def video_feed():
    # Fix ambil objek user Asli biar ga ilang di tengah jalan
    real_user = current_user._get_current_object()
    return Response(generate_frames(real_user), mimetype='multipart/x-mixed-replace; boundary=frame')

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
    if current_user.role != 'admin': return redirect(url_for('root'))
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

# @app.route('/manajer')
# @login_required
# def manajer_dashboard():
#     if current_user.role != 'manajer': return "⛔ AKSES DITOLAK"
#     conn = create_connection()
#     today_str = datetime.now().strftime("%Y-%m-%d")
#     query = f"""
#     SELECT u.name, MIN(a.time_str) as face_in, MAX(a.time_str) as face_out, COUNT(a.id) as total_scan
#     FROM attendance a JOIN users u ON a.user_id = u.id
#     WHERE a.date_str = '{today_str}' GROUP BY u.name
#     """
#     df = pd.read_sql_query(query, conn)
#     conn.close()
#     attendance_data = df.to_dict(orient='records')
#     return render_template('manajer_dashboard.html', user=current_user, data=attendance_data, today=today_str)

@app.route('/download_report/<type>/<month>')
@login_required
def download_report(type, month):
    if current_user.role != 'manajer': return "⛔ AKSES DITOLAK"
    
    conn = create_connection()
    
    # Query Data Lengkap (Filter Bulan & Role Karyawan)
    # Kita tambahkan WHERE u.role = 'karyawan' biar Admin/Manajer gak ikut ke-download
    query = f"""
    SELECT 
        u.name as Nama, 
        a.date_str as Tanggal,
        a.time_str as Jam_Scan,
        u.role as Jabatan
    FROM attendance a
    JOIN users u ON a.user_id = u.id
    WHERE u.role = 'karyawan' AND a.date_str LIKE '{month}%'
    ORDER BY a.date_str DESC, a.time_str ASC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()

    filename = f"Laporan_Absensi_{month}"

    if type == 'excel':
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Rekap Bulanan')
        output.seek(0)
        return send_file(output, download_name=f'{filename}.xlsx', as_attachment=True)

    elif type == 'pdf':
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", style="B", size=16)
        pdf.cell(200, 10, txt=f"Laporan Bulanan Tiaria Jewelry", ln=True, align='C')
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"Periode: {month}", ln=True, align='C')
        pdf.ln(10)

        # Header Tabel
        pdf.set_font("Arial", style="B", size=10)
        pdf.cell(50, 10, "Nama", 1)
        pdf.cell(40, 10, "Tanggal", 1)
        pdf.cell(40, 10, "Jam", 1)
        pdf.cell(40, 10, "Jabatan", 1)
        pdf.ln()

        # Isi Tabel
        pdf.set_font("Arial", size=10)
        for i, row in df.iterrows():
            pdf.cell(50, 10, str(row['Nama']), 1)
            pdf.cell(40, 10, str(row['Tanggal']), 1)
            pdf.cell(40, 10, str(row['Jam_Scan']), 1)
            pdf.cell(40, 10, str(row['Jabatan']), 1)
            pdf.ln()

        pdf_output = BytesIO()
        pdf_output.write(pdf.output(dest='S').encode('latin-1'))
        pdf_output.seek(0)
        return send_file(pdf_output, download_name=f'{filename}.pdf', as_attachment=True, mimetype='application/pdf')

@app.route('/manajer', methods=['GET', 'POST'])
@login_required
def manajer_dashboard():
    if current_user.role != 'manajer': return "⛔ AKSES DITOLAK"
    
    conn = create_connection()
    
    # 1. Cek Filter Bulan
    if request.method == 'POST':
        filter_month = request.form['bulan'] 
    else:
        filter_month = datetime.now().strftime("%Y-%m")
    
    # --- QUERY 1: REKAP BULANAN (KHUSUS KARYAWAN) ---
    query_rekap = f"""
    SELECT 
        u.name, 
        COALESCE(SUM(CASE WHEN t.in_time != t.out_time THEN 1 ELSE 0 END), 0) as total_hadir,
        MIN(t.in_time) as rata_rata_jam_masuk
    FROM users u
    LEFT JOIN (
        SELECT user_id, date_str, MIN(time_str) as in_time, MAX(time_str) as out_time
        FROM attendance
        WHERE date_str LIKE '{filter_month}%'
        GROUP BY user_id, date_str
    ) t ON u.id = t.user_id
    WHERE u.role = 'karyawan'  -- <--- INI FILTERNYA BRO!
    GROUP BY u.name
    """
    
    df_rekap = pd.read_sql_query(query_rekap, conn)
    df_rekap['total_hadir'] = df_rekap['total_hadir'].fillna(0).astype(int)
    rekap_data = df_rekap.to_dict(orient='records')
    
    # --- QUERY 2: DETAIL HARIAN (KHUSUS KARYAWAN) ---
    query_daily = f"""
    SELECT 
        u.name, 
        a.date_str,
        MIN(a.time_str) as face_in,
        MAX(a.time_str) as face_out
    FROM attendance a
    JOIN users u ON a.user_id = u.id
    WHERE u.role = 'karyawan' AND a.date_str LIKE '{filter_month}%' -- <--- FILTER DI SINI JUGA
    GROUP BY u.name, a.date_str
    ORDER BY a.date_str DESC, a.time_str ASC
    """
    df_daily = pd.read_sql_query(query_daily, conn)
    daily_data = df_daily.to_dict(orient='records')
    
    conn.close()
    
    return render_template('manajer_dashboard.html', 
                           user=current_user, 
                           rekap_data=rekap_data,   
                           daily_data=daily_data,   
                           selected_month=filter_month)

    filename = f"Laporan_Absensi_{month}"

    if type == 'excel':
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Rekap Bulanan')
        output.seek(0)
        return send_file(output, download_name=f'{filename}.xlsx', as_attachment=True)

    elif type == 'pdf':
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", style="B", size=16)
        pdf.cell(200, 10, txt=f"Laporan Bulanan Tiaria Jewelry", ln=True, align='C')
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"Periode: {month}", ln=True, align='C')
        pdf.ln(10)

        # Header Tabel
        pdf.set_font("Arial", style="B", size=10)
        pdf.cell(50, 10, "Nama", 1)
        pdf.cell(40, 10, "Tanggal", 1)
        pdf.cell(40, 10, "Jam", 1)
        pdf.cell(40, 10, "Jabatan", 1)
        pdf.ln()

        # Isi Tabel
        pdf.set_font("Arial", size=10)
        for i, row in df.iterrows():
            pdf.cell(50, 10, str(row['Nama']), 1)
            pdf.cell(40, 10, str(row['Tanggal']), 1)
            pdf.cell(40, 10, str(row['Jam_Scan']), 1)
            pdf.cell(40, 10, str(row['Jabatan']), 1)
            pdf.ln()

        pdf_output = BytesIO()
        pdf_output.write(pdf.output(dest='S').encode('latin-1'))
        pdf_output.seek(0)
        return send_file(pdf_output, download_name=f'{filename}.pdf', as_attachment=True, mimetype='application/pdf')
if __name__ == '__main__':
    app.run(debug=True)