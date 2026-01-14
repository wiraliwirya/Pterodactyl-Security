# Pterodactyl Security Patch

Project ini menyediakan skrip instalasi otomatis untuk meningkatkan keamanan dan manajemen izin pada panel Pterodactyl. Skrip ini memodifikasi kontroler inti dan layanan untuk memastikan validasi hak akses yang lebih ketat, khususnya membatasi tindakan kritis hanya untuk **Root Administrator** dan pemilik server yang sah.

<div align="center">

### Credits

<a href="https://github.com/mwildanhidayat">
  <img src="https://github.com/mwildanhidayat.png" width="100px;" alt="mwildanhidayat"/><br />
  <sub><b>mwildanhidayat</b></sub>
</a>
<br>
<a href="https://github.com/liwirya">
  <img src="https://github.com/liwirya.png" width="100px;" alt="liwirya"/><br />
  <sub><b>liwirya</b></sub>
</a>

</div>

---

## 🛡️ Fitur Utama

Skrip ini melakukan *patching* pada file inti Pterodactyl untuk menegakkan aturan keamanan berikut:

1.  **Proteksi Penghapusan Server (`ServerDeletionService`)**:
    * Mencegah penghapusan server oleh pengguna yang tidak berhak.
    * Hanya Root Admin atau Pemilik Server yang dapat menghapus server.

2.  **Manajemen Pengguna Terproteksi (`UserController`)**:
    * Hanya Root Admin yang dapat menghapus pengguna.
    * Hanya Root Admin yang dapat memodifikasi kolom sensitif (email, username, password, status admin).
    * Mencegah Admin menghapus akun mereka sendiri jika masih memiliki server aktif.

3.  **Akses Administrator Terbatas**:
    * **Lokasi (`LocationController`)**: Hanya Root Admin yang dapat membuat, melihat, mengubah, atau menghapus lokasi.
    * **Node (`NodeController`)**: Hanya Root Admin yang dapat mengelola node.
    * **Nests (`NestController`)**: Hanya Root Admin yang dapat mengelola nests & eggs.
    * **Pengaturan Panel (`SettingsController`)**: Hanya Root Admin yang dapat mengubah konfigurasi panel global.

4.  **Keamanan File Manager (`FileController`)**:
    * Validasi ketat pada setiap operasi file (read, write, download, delete, compress, dll).
    * Memastikan hanya Pemilik Server atau Root Admin yang dapat mengakses file server (mencegah akses lintas server yang tidak sah).

5.  **Sistem Backup Otomatis**:
    * Secara otomatis mem-backup file asli sebelum melakukan modifikasi.
    * File backup disimpan dengan timestamp untuk pemulihan mudah.

## 🛠️ Teknologi yang Digunakan

* **Bash Shell Script**: Untuk logika instalasi, pengecekan lingkungan, dan pencadangan file.
* **PHP 8.1+**: Bahasa pemrograman utama yang digunakan oleh Pterodactyl.
* **Laravel Framework**: Arsitektur dasar Pterodactyl yang dimodifikasi (Controllers, Services, Requests).

## 📋 Prasyarat Instalasi

Sebelum menjalankan installer, pastikan sistem Anda memenuhi syarat berikut:

* **Akses Root**: Skrip harus dijalankan sebagai root (sudo).
* **Pterodactyl Panel**: Harus sudah terinstal di `/var/www/pterodactyl` (atau sesuaikan path di variabel environment).
* **PHP**: Versi 8.1 atau lebih baru.
* **Permissions**: Izin tulis (write permission) pada direktori instalasi Pterodactyl.

## 📂 Susunan Project

Struktur file dalam repositori ini cukup sederhana:

```text
.
├── LICENSE                     # Lisensi MIT
├── README.md                   # Dokumentasi proyek ini
└── pterodactyl_installer.sh    # Skrip utama (Installer & Patcher)

```

> **Catatan:** File `pterodactyl_installer.sh` berisi *heredocs* yang menanamkan kode PHP yang telah dimodifikasi langsung ke dalam file tujuan di server Anda.

## 🚀 Instalasi & Penggunaan

Ikuti langkah-langkah berikut untuk menerapkan patch keamanan:

1. **Unduh atau Clone Repository**:
```bash
git clone [https://github.com/liwirya/pterodactyl-security.git](https://github.com/liwirya/pterodactyl-security.git)
cd pterodactyl-security

```


2. **Berikan Izin Eksekusi**:
```bash
chmod +x pterodactyl_installer.sh

```


3. **Jalankan Installer**:
Jalankan skrip sebagai root.
```bash
sudo ./pterodactyl_installer.sh

```


4. **Verifikasi**:
* Skrip akan mencetak log instalasi.
* Cek file log di `/var/log/pterodactyl-protection-install.log`.
* Cache Laravel akan dibersihkan secara otomatis di akhir proses.



### Pemulihan (Rollback)

Jika terjadi kesalahan, skrip ini membuat backup file asli di direktori:
`/var/www/pterodactyl/backups/`
Anda dapat mengembalikan file asli dengan menyalin file berekstensi `.backup_TIMESTAMP` kembali ke nama aslinya.

## 🤝 Kontribusi

Kontribusi sangat dipersilakan! Jika Anda ingin meningkatkan keamanan atau menambahkan fitur baru:

1. Fork repository ini.
2. Buat branch fitur baru (`git checkout -b fitur-keren`).
3. Commit perubahan Anda (`git commit -m 'Menambahkan fitur keren'`).
4. Push ke branch (`git push origin fitur-keren`).
5. Buat Pull Request.

## 📄 Lisensi

Proyek ini dilisensikan di bawah **MIT License**.

Copyright (c) 2026 **WIRA LIWIRYA**

Izin diberikan secara cuma-cuma kepada siapa pun yang mendapatkan salinan perangkat lunak ini dan file dokumentasi terkait, untuk menggunakan perangkat lunak tanpa batasan, termasuk hak untuk menggunakan, menyalin, memodifikasi, menggabungkan, menerbitkan, mendistribusikan, mensublisensikan, dan/atau menjual salinan Perangkat Lunak.

Lihat file [LICENSE](https://www.google.com/search?q=LICENSE) untuk detail lengkap.
