import cv2
import face_recognition
import os
import pickle
import numpy as np

# Lokasi folder foto karyawan 
DATASET_PATH = 'dataset'
# Lokasi file penyimpanan hasil training (biar cepet loadnya)
ENCODINGS_PATH = 'utils/encoding.pickle'

def load_face_encoding():
    """ Load Databse wajah yang sudah di training """
    if os.path.exists(ENCODINGS_PATH):
        print("📂 Loading data wajah yang sudah ada...")
        data = pickle.loads(open(ENCODINGS_PATH, "rb").read())
        return data
    else: 
        print("⚠️ Belum ada data wajah. Silakan training dulu.")
        return {"encodings": [], "names": []}
    
def train_faces():
    """
    Fungsi ini akan membaca semua folder di 'dataset', mendeteksi wajah, dan 
    menyampaikan ke file pickle
    """

    known_encodings = []
    known_names = []

    print("📸 Memulai proses training wajah...")

    # Cek apakah folder dataset ada isinya
    if not os.path.exists(DATASET_PATH): 
        os.makedirs(DATASET_PATH)
        print(f"📁 Folder '{DATASET_PATH}' baru dibuat. Masukkan foto karyawan di sana!")
        return
    
    # Loop setiap folder karyawan (misal: dataset/Budi, dataset/Siti)
    for name in os.listdir(DATASET_PATH):
        user_folder = os.path.join(DATASET_PATH, name)

        # Pastikan yang dibaca isi nya adalah folder
        if not os.path.isdir(user_folder):
            continue
        print(f"   👤 Memproses karyawan: {name}")

        # Loop setiap foto di dalam folder karyawan
        for filename in os.listdir(user_folder):
            image_path = os.path.join(user_folder, filename)

            # load gambar
            image = cv2.imread(image_path)
            if image is None: 
                continue

            # Konversi BGR (OpenCV) ke RGB (face_recognition)
            rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)

            # Deteksi kotak wajah
            boxes = face_recognition.face_locations(rgb, model="hog")

            # Hitung encodings (kode unik wajah)
            encodings = face_recognition.face_encodings(rgb, boxes)

            # Simpan encoding dan naamanya
            for encoding in encodings:
                known_encodings.append(encoding)
                known_names.append(name)

    # Simpan hasil training ke file (biar besok gak perlu training ulang)
    print("💾 Menyimpan data wajah...")
    data = {"encodings": known_encodings, "names": known_names}
    f = open(ENCODINGS_PATH, "wb")
    f.write(pickle.dumps(data))
    f.close()
    print("✅ Training Selesai! Sistem sudah kenal wajah karyawan.")

# Biar bisa dijalankan langsung lewat terminal
if __name__ == "__main__":
    train_faces()
