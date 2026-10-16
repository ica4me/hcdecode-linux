## Pipeline

1. File dibaca sebagai UTF-8. Karakter hasil decode dikonversi menjadi byte Latin-1.
2. Byte di-XOR dengan kunci berulang profil untuk mendapatkan teks heksadesimal.
3. Teks heksadesimal diubah menjadi `ciphertext || tag16` dan dibuka dengan kunci outer.
4. Plaintext menghasilkan JSON dengan key `a` dan `b`. Field `a.xy` berisi
   konfigurasi utama; field lain di `a` dan `b` merupakan record terenkripsi.
5. Buka `a.xy` dengan kunci main. Pemisah 32 kolom adalah **nilai a.uv yang masih
   terenkripsi**, bukan plaintext metadata `uv`.
6. Buka record terenkripsi di setiap kolom dengan kunci field. Kolom Psiphon
   tertentu berisi dua record terpisah, masing-masing dengan tag sendiri.
7. Jika ada, lepaskan representasi JKL: decode Base64, XOR berulang, decode
   Base64 kembali. Kredensial SSH tertentu juga memakai representasi nibble
   Braille dan pasangan angka.
8. Parse SSH serta JSON V2Ray. Simpan semua 32 kolom agar data yang belum diberi
   nama semantik tetap dapat diperiksa.

## Detail MAC yang menentukan kompatibilitas

Profil ini memakai nonce **8 byte**, key **32 byte**, dan tag **16 byte**.
Dengan AAD kosong, pesan yang diautentikasi adalah:

```text
LE64(0) || ciphertext || LE64(len(ciphertext))
```

Tidak ada padding RFC 8439. Kunci sekali pakai Poly1305 adalah 32 byte pertama
keystream ChaCha20; dekripsi payload dimulai pada offset keystream 64 byte.
Semua tag diperiksa sebelum plaintext terkait diterima.

API `Crypto.Cipher.ChaCha20_Poly1305` memakai layout MAC RFC, termasuk ketika
nonce panjangnya 8 byte. Karena itu tool memakai ChaCha20 stream dan Poly1305
secara terpisah untuk kompatibilitas dengan format input ini. Kode ini hanya
membuka format lama; nonce statis tersebut tidak boleh dijadikan desain
enkripsi baru.

## Kolom yang dipetakan

| Indeks mulai 0 | Isi |
| --- | --- |
| 0 | Payload HTTP, termasuk placeholder mentah |
| 1 | Remote proxy |
| 4 | Masa berlaku konfigurasi |
| 6 | HTML catatan |
| 7 | Kredensial SSH |
| 10, 11 | Konfigurasi dan kredensial OpenVPN |
| 12 | SNI mentah, dapat berupa placeholder |
| 18 | Nama konfigurasi |
| 20 | Nilai mode koneksi mentah |
| 24 | Gabungan field Psiphon |
| 25, 26 | Flag V2Ray dan JSON V2Ray |
| 27 | Nilai versi konfigurasi |
| 28–31 | Field SlowDNS/resolver yang diamati |

Pemetaan mode/flag tambahan sengaja tidak ditebak. Objek V2Ray dipertahankan
sehingga protocol, servers, streamSettings, policy, dan bagian lain tidak hilang.

## Sumber dan asal implementasi

- Layout HC, konstanta profil, dan transformasi field diverifikasi terhadap
  file yang diberikan dalam sesi analisis. Referensi pembanding sebelumnya:
  https://github.com/Matrixzat/vpn-decryptor/tree/main/vendor/spdecode_python/spdecode
- Perbedaan MAC original dan RFC, dokumentasi resmi PyCryptodome:
  https://www.pycryptodome.org/src/cipher/chacha20_poly1305
- ChaCha20 stream dan seek:
  https://www.pycryptodome.org/src/cipher/chacha20
- Verifikasi tag Poly1305, dokumentasi resmi cryptography:
  https://cryptography.io/en/latest/hazmat/primitives/mac/poly1305/

Konstanta profil bukan kredensial akun pengguna. Kode paket disusun ulang
khusus untuk decoder kecil ini; tidak membundel kode maupun biner APK.
