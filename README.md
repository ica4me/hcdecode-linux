# HCDecode Linux

Decoder `.hc` offline dengan CLI dan API Python.

## Instalasi Linux

Prasyarat: Python 3.10 atau lebih baru, modul `venv`, dan pip. Pengujian dilakukan
pada Linux/Python 3.12. Instalasi dependensi membutuhkan akses indeks paket;
setelah dependensi tersedia, proses decode berjalan offline.

```bash
apt-get update
apt install git -y
mkdir -p /root/hc-decoder
cd /root/hc-decoder
git clone https://github.com/ica4me/hcdecode-linux.git hcdecode-linux
cd hcdecode-linux
apt install python3.13-venv -y
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
hcdecode --version
```

Untuk memakai versi dependensi yang persis diuji, jalankan
`python -m pip install -r requirements-tested.txt` sebelum `python -m pip install .`.

## Contoh file uji coba

```bash
hcdecode decode examples/demo_ssh.hc -o demo_ssh.json
```

Output status pada stderr:

```text
OK: demo_ssh.hc: 32 fields, 17 MAC valid -> demo_ssh.json
```

`demo_ssh.json` berisi SSH `vpn.example.com:443` dan kredensial `[REDACTED]`.
Semua file dalam `examples/` memakai domain contoh dan akun fiktif.

## Decrypt File 

```bash
# Default: tampilkan JSON dengan kredensial disamarkan.
hcdecode decode "konfigurasi.hc"

# Simpan laporan; file hasil dibuat dengan izin 0600.
hcdecode decode "konfigurasi.hc" -o hasil.json

# Pulihkan seluruh isi asli secara lokal, termasuk kredensial dan HTML Note.
hcdecode decode examples/xlaab01.hc --show-secrets -o  examples/xlaab01.full.json

# Ekspor hanya JSON V2Ray asli, tanpa pembungkus laporan.
hcdecode decode examples/demo_trojan.hc --v2ray-only --show-secrets -o examples/v2ray.json

# Batch: proses semua file; jika satu gagal, file lain tetap diproses.
hcdecode decode /path/config/*.hc --out-dir hasil

# Lihat cakupan profil.
hcdecode profiles
```

File yang sudah ada tidak ditimpa. Gunakan nama atau folder keluaran baru untuk
pengulangan. Exit code `0` berarti semua input berhasil; `1` berarti ada file
gagal; `2` berarti argumen CLI tidak valid. Log status/error tidak mencetak
plaintext. `--show-secrets` mengubah isi keluaran yang memang Anda pilih untuk
ditampilkan atau disimpan.

`--v2ray-only` tanpa `--show-secrets` menghasilkan JSON dengan password disamarkan.
JSON asli yang diekspor mempertahankan isi konfigurasi HC; pengaturan seperti
`inbounds` dapat perlu disesuaikan sebelum dipakai oleh client Linux. Decoder
tidak menguji koneksi maupun masa berlaku akun.

## Struktur kode

| Lokasi | Tanggung jawab |
| --- | --- |
| `hcdecode/cli.py` | Argumen, pemrosesan batch, keluaran eksklusif dengan izin 0600 |
| `hcdecode/profile.py` | Kunci format, nonce, XOR, jumlah field, dan batas ukuran |
| `hcdecode/crypto.py` | Verifikasi MAC dan dekripsi ChaCha20-Poly1305 original |
| `hcdecode/encodings.py` | Lapisan JKL serta representasi kredensial lama |
| `hcdecode/decoder.py` | Envelope, metadata, 32 field, pemetaan SSH dan JSON V2Ray |
| `hcdecode/reporting.py` | Pilihan salinan tersamarkan atau isi asli |
| `hcdecode/errors.py` | Error format, autentikasi, dan parsing |
| `tests/` | Pengujian integritas, representasi, privasi keluaran, dan CLI |
| `examples/` | Dua file HC fiktif: SSH dan Trojan |
| `docs/FORMAT.md` | Penjelasan format dan detail kriptografi |
| `docs/DEVELOPMENT.md` | Rencana penambahan profil dan adapter sniff |
| `docs/VALIDATION.json` | Hasil validasi paket ini |

## API Python

```python
from hcdecode import decode_file
from hcdecode.reporting import render

decoded = decode_file("examples/demo_trojan.hc")
safe = render(decoded)  # Default: kredensial tersamarkan.
print(safe["connection"]["v2ray"]["outbounds"][0]["protocol"])
# Output: trojan
```

`decode_file()` dan `decode_bytes()` mengembalikan isi asli di memori. Panggil
`render()` untuk keluaran tersamarkan. Kode tidak menjanjikan penghapusan byte
rahasia dari memori Python; jangan mencatat objek mentah jika tidak diperlukan.

## Pengujian

```bash
python -m unittest discover -s tests -v
```

Fixture kriptografi dan HC fiktif dibuat menggunakan **libsodium original
ChaCha20-Poly1305**, terpisah dari implementasi decoder yang memakai
PyCryptodome + cryptography. Libsodium tidak diperlukan saat menjalankan tool
atau tests: fixture sudah disertakan.

## Batas dukungan

- Mendukung layout legacy `a/b`, 32 field, nonce statis 64-bit yang diamati.
- Format `HCCFG`, `cfg/content`, atau nonce turunan password/HWID belum didukung.
- Input dibatasi 16 MiB. Tag gagal tidak diabaikan dan hasil parsial tidak
  dilaporkan sebagai sukses.
- Flag yang maknanya belum dipastikan dipertahankan dengan nama `field_*_unmapped`.
- `lifeTime` adalah nilai dalam konfigurasi; tidak menyatakan akun server aktif.
- Paket ini belum melakukan **live memory sniff**. Arah pengembangannya dijelaskan
  dalam `docs/DEVELOPMENT.md`.
- Default redaction mencakup field kredensial yang dikenali, salinannya, nomor
  kontak `wa.me`, dan HTML catatan. Format atau lokasi rahasia baru memerlukan
  pembaruan aturan; jangan menganggap ini anonimisasi universal.

---
## Install UI (Opsional)

<img width="960" height="540" alt="UI-HCdecoder" src="https://github.com/user-attachments/assets/1cd7b5b0-a098-43e5-8313-ba5711a65b67" />

```bash
# Install Docker
apt install wget -y
curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh

# Download UI
cd /root/hc-decoder
wget https://github.com/ica4me/hcdecode-linux/releases/download/ui/hcdecode-web.zip
unzip hcdecode-web.zip
cd hcdecode-web

cp .env.example .env
docker compose config --quiet
docker compose up -d --build
docker compose ps
```
Konfigurasi .env arahkan ke lokasi backend:
```bash
HC_BACKEND_PATH=/root/hc-decoder/hcdecode-linux
WEB_BIND=0.0.0.0
WEB_PORT=8080
```
Akses UI http://ip-server:8080

## Download HTTP Custom versi lama (Android)
```bash
wget https://github.com/ica4me/hcdecode-linux/releases/download/apk/HTTP.Custom-version.4.11.25.build.645.apk
```