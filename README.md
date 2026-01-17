# Pterodactyl Security & Resource Limiter

![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Bash](https://img.shields.io/badge/Language-Bash-green?style=flat-square)
![Pterodactyl](https://img.shields.io/badge/Platform-Pterodactyl-blueviolet?style=flat-square)

**Pterodactyl Security & Resource Limiter** adalah kumpulan *tools* otomatisasi berbasis Bash untuk meningkatkan keamanan dan manajemen resource pada panel Pterodactyl Anda. Project ini terdiri dari dua modul utama:
1. **Security Enhancer**: Memperketat *Role-Based Access Control* (RBAC) untuk memastikan hanya **Root Admin** yang dapat melakukan tindakan kritis.
2. **Resource Limiter**: Mencegah pembuatan server dengan resource *unlimited* (0 MB/0%) oleh admin biasa.

Solusi ini sangat ideal untuk penyedia hosting game yang ingin mencegah penyalahgunaan akses oleh staff atau sub-admin.

## 🌟 Fitur Utama

### 🛡️ Security Enhancer (`install.sh`)
Modul ini memodifikasi *core files* untuk membatasi akses berikut hanya kepada **Root Administrator (ID: 1)**:
* **Penghapusan Server:** Mencegah admin biasa menghapus server sembarangan.
* **Manajemen User:** Hanya Root Admin yang bisa membuat, mengedit, atau menghapus user.
* **Infrastruktur:** Pengaturan *Locations*, *Nodes*, dan *Nests* terkunci.
* **Panel Settings:** Mencegah perubahan konfigurasi global panel.
* **File Access:** Validasi ketat kepemilikan file server melalui API.

### ⛔ Resource Limiter (`limit.sh`)
Modul ini memvalidasi input saat pembuatan atau edit server:
* **No Unlimited Resources:** Admin biasa **wajib** mengisi batas RAM, Disk, dan CPU (tidak boleh `0`).
* **Root Privilege:** Hanya Super Admin yang diizinkan membuat server dengan spesifikasi *unlimited*.
* **Validasi Real-time:** Pengecekan dilakukan langsung saat *request* pembuatan atau update *build* server.

## 🛠️ Teknologi yang Digunakan

* **Bash Scripting:** Otomatisasi instalasi, backup, dan pemulihan.
* **PHP 8.1+:** Logika backend yang dimodifikasi.
* **Laravel Framework:** Basis dari Pterodactyl Panel.

## 📋 Prasyarat Instalasi

Sebelum menjalankan skrip, pastikan sistem Anda memenuhi syarat berikut:
1. **Akses Root:** Wajib menggunakan user `root` atau `sudo`.
2. **Pterodactyl Panel:** Terinstal di direktori standar (`/var/www/pterodactyl`).
3. **PHP 8.1+:** Versi PHP yang kompatibel dengan Pterodactyl.

## 📂 Susunan Project

```text
.
├── install.sh                  # Installer modul Security Enhancer
├── limit.sh                    # Installer modul Resource Limiter
├── LICENSE                     # Lisensi MIT
└── README.md                   # Dokumentasi Project

```

## 🚀 Cara Penggunaan

Clone repositori ini terlebih dahulu ke server panel Anda:

```bash
git clone [https://github.com/liwirya/pterodactyl-security.git](https://github.com/liwirya/pterodactyl-security.git)
cd pterodactyl-security
chmod +x install.sh limit.sh

```

### 1. Instalasi Security Enhancer

Jalankan skrip ini untuk mengamankan fitur-fitur panel:

```bash
sudo ./install.sh

```

### 2. Instalasi Resource Limiter

Jalankan skrip ini untuk membatasi pembuatan server unlimited:

```bash
sudo ./limit.sh

```

> **Catatan:** Kedua skrip akan secara otomatis membuat backup dari file asli yang dimodifikasi. Jika terjadi error, Anda dapat memulihkan file dari folder backup yang dibuat (biasanya berekstensi `.backup_TIMESTAMP`).

## 👥 Kredit

Project ini dikembangkan dan dikelola oleh:

<table>
<tr>
<td align="center">
<a href="https://www.google.com/search?q=https://github.com/liwirya">
<img src="https://www.google.com/search?q=https://github.com/liwirya.png%3Fsize%3D100" width="100px;" alt="Liwirya"/><br />
<sub><b>Liwirya</b></sub>
</a>
</td>
<td align="center">
<a href="https://www.google.com/search?q=https://github.com/mwildanhidayat">
<img src="https://www.google.com/search?q=https://github.com/mwildanhidayat.png%3Fsize%3D100" width="100px;" alt="mwildanhidayat"/><br />
<sub><b>mwildanhidayat</b></sub>
</a>
</td>
</tr>
</table>

## 🤝 Kontribusi

Kontribusi sangat terbuka! Silakan fork repository ini dan buat *Pull Request* jika Anda memiliki perbaikan atau fitur baru.

1. Fork Project
2. Buat Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit Perubahan (`git commit -m 'Add some AmazingFeature'`)
4. Push ke Branch (`git push origin feature/AmazingFeature`)
5. Buka Pull Request

## 📄 Lisensi

Didistribusikan di bawah Lisensi MIT. Lihat `LICENSE` untuk informasi lebih lanjut.

```text
MIT License
Copyright (c) 2026 WIRA LIWIRYA

```
