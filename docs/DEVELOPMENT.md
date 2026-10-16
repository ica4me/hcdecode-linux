# Pengembangan berikutnya

## Pisahkan sumber data dan parser

Urutan pengembangan yang disarankan:

1. Tambahkan registry profil jika sudah ada sampel format kedua yang dapat
   diverifikasi. Pemilihan profil perlu memeriksa envelope dan hasil autentikasi.
2. Pisahkan adapter input seperti file, dump memori milik sendiri, atau stream
   dari perangkat. Adapter tidak boleh langsung menulis output publik.
3. Untuk dump, buat parser dengan format dan batas panjang eksplisit. Jangan
   mengasumsikan satu alamat relatif atau ukuran 10.000 byte mencakup semuanya.
4. Tambahkan status `complete`, `partial`, dan `unsupported` jika parser dump
   memang memiliki hasil parsial; jangan menyamakannya dengan decode HC valid.
5. Gunakan API yang sama untuk UI desktop atau API localhost setelah CLI stabil.

## Decode file dan sniff di Linux

Paket ini tidak mengimplementasikan adapter ADB, Frida, GameGuardian, atau
pengambil memori. Tambahkan adapter tersebut sebagai pekerjaan terpisah setelah
perangkat uji dan metode akses proses ditetapkan. Pipeline live sniff juga
tidak identik dengan menangkap paket jaringan.

Dokumentasi resmi ADB:
https://developer.android.com/tools/adb

## Pengujian untuk profil baru

- Minimal satu sampel yang hasilnya diketahui dan satu vektor crypto independen.
- Perubahan satu byte pada ciphertext/tag harus gagal secara eksplisit.
- Uji kolom kosong, Unicode, catatan panjang, jumlah kolom baru, serta JSON rusak.
- Periksa semua lokasi rahasia sebelum menambahkan aturan default redaction.
- Uji versi runtime Linux yang benar-benar akan dipakai; dukungan deklaratif
  Python 3.10+ tidak sama dengan sudah menguji setiap versi dan distribusi.
