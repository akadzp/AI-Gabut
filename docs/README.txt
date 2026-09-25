AI-GABUT — DOCUMENTATION
========================

Dokumentasi ini merupakan panduan utama untuk memahami project
AI-Gabut sebelum membaca source code atau melakukan perubahan
terhadap sistem.

Dokumentasi dibuat agar developer maupun AI lain dapat melanjutkan
project tanpa harus bergantung pada percakapan atau pengetahuan
pribadi dari pembuat sebelumnya.


TUJUAN DOKUMENTASI
------------------

Dokumentasi AI-Gabut mempunyai tiga fungsi utama:

1. Menjelaskan bagaimana sistem dirancang dan bekerja.
2. Menjelaskan apa yang akan dibangun dan urutan pembangunannya.
3. Menjelaskan kondisi project saat ini.

Karena ketiga hal tersebut mempunyai fungsi yang berbeda,
dokumentasi dipisahkan menjadi tiga bagian:

    technical/
    roadmaps/
    status/


STRUKTUR DOKUMENTASI
--------------------

docs/
│
├── README.txt
│
├── technical/
│
├── roadmaps/
│
└── status/


1. TECHNICAL
------------

Folder `technical/` menjelaskan sistem.

Pertanyaan utama yang dijawab:

    "AI-Gabut ini apa?"
    "Bagaimana arsitekturnya?"
    "Apa fungsi masing-masing subsystem?"
    "Bagaimana hubungan antar bagian?"
    "Apa aturan dependency-nya?"

Dokumen di dalam folder ini menjelaskan:

- project context
- system architecture
- subsystem boundaries
- dependency
- core
- application
- connector
- data
- runtime
- workspace
- dan konsep teknis lainnya

Dokumen technical menjelaskan bagaimana sistem dirancang,
bukan status pembangunan sistem.

Technical documentation tidak digunakan untuk menentukan apakah
sebuah pekerjaan sudah selesai atau belum.


2. ROADMAPS
-----------

Folder `roadmaps/` menjelaskan rencana pembangunan AI-Gabut.

File utama:

    00_Roadmap-Besar.txt

File tersebut merupakan roadmap utama yang menjelaskan
kelompok besar pekerjaan yang akan dibangun.

Roadmap besar tidak mematok jumlah tahap sejak awal.

Jumlah dan pembagian tahap dapat berubah apabila proses pembangunan
menunjukkan bahwa sebuah bagian perlu dipecah, digabung, atau
ditambahkan.

Roadmap detail menggunakan pola:

    01_Roadmap-....txt
    02_Roadmap-....txt
    03_Roadmap-....txt
    ...

Dokumen detail tidak harus dibuat seluruhnya sejak awal.

Dokumen tersebut dibuat ketika suatu tahap sudah cukup jelas untuk
didokumentasikan sebagai proses pembangunan tersendiri.

Setiap roadmap detail mendokumentasikan satu tahap dari awal
sampai selesai, termasuk:

- tujuan
- prerequisite
- dependency
- tahapan pekerjaan
- implementasi
- integrasi
- validation
- definition of done
- kondisi selesai

Roadmap adalah rencana.

Roadmap bukan bukti bahwa suatu pekerjaan sudah selesai.


3. STATUS
---------

Folder `status/` menjelaskan kondisi aktual project.

Pertanyaan utama:

    "Sekarang project sudah sampai mana?"

Status digunakan untuk menunjukkan hubungan antara kondisi aktual
project dengan roadmap.

Status dapat mencatat:

- completed
- current
- next
- planned
- blocked
- validation status
- catatan penting mengenai kondisi project

Status harus menggambarkan kondisi nyata project.

Status bukan tempat mendesain arsitektur dan bukan tempat membuat
rencana pembangunan baru.


HUBUNGAN KETIGA BAGIAN
----------------------

Ketiga bagian dokumentasi saling melengkapi:

    technical/
        ↓
    bagaimana sistem bekerja

    roadmaps/
        ↓
    apa yang akan dibangun dan bagaimana urutannya

    status/
        ↓
    sudah sampai mana sekarang


ALUR MEMBACA PROJECT
--------------------

Developer atau AI baru sebaiknya membaca project dengan urutan:

    1. docs/README.txt
           ↓
    2. docs/technical/
           ↓
    3. docs/roadmaps/00_Roadmap-Besar.txt
           ↓
    4. docs/status/00_Current-Status.txt
           ↓
    5. roadmap detail yang sedang relevan
           ↓
    6. Tree project
           ↓
    7. source code


MENGAPA URUTAN INI DIGUNAKAN
----------------------------

Technical documentation memberikan pemahaman tentang sistem.

Roadmap memberikan pemahaman tentang arah pembangunan.

Status memberikan pemahaman tentang posisi aktual.

Setelah ketiganya dipahami, Tree dan source code dapat dibaca
dengan konteks yang benar.

Dengan demikian developer atau AI yang baru masuk ke project tidak
perlu mengetahui percakapan atau keputusan sebelumnya untuk dapat
memahami kondisi project.


AI-GABUT DAN APPLICATION
------------------------

AI-Gabut merupakan platform.

Platform menyediakan capability yang dapat digunakan oleh berbagai
application.

Contoh:

    AI-Gabut
       │
       ├── Agentic
       │
       ├── BukaOlshop CS
       │
       └── Application lainnya

Application bukan bagian dari generic identity AI-Gabut.

Application dapat mempunyai:

- identity
- domain
- policy
- configuration
- interface
- deployment environment

Sedangkan capability generik tetap berada di core AI-Gabut.


TREE SEBAGAI KONDISI AKTUAL
---------------------------

Tree dan source code menunjukkan kondisi aktual project.

Dokumentasi menjelaskan dan memberikan konteks terhadap kondisi
tersebut.

Apabila dokumentasi tidak sesuai dengan kondisi source code atau
Tree, dokumentasi harus diperbarui.

Jangan menganggap dokumentasi lebih benar daripada implementasi
aktual tanpa melakukan pemeriksaan.


ATURAN PEMELIHARAAN DOKUMENTASI
-------------------------------

Setiap perubahan besar pada arsitektur harus diikuti dengan
pembaruan technical documentation.

Setiap perubahan arah pembangunan harus diikuti dengan pembaruan
roadmap.

Setiap perubahan kondisi pembangunan harus diikuti dengan
pembaruan status.

Jangan mencampurkan ketiga fungsi tersebut.

Gunakan:

    technical/
        untuk HOW / WHAT THE SYSTEM IS

    roadmaps/
        untuk WHAT WILL BE BUILT / HOW IT WILL BE BUILT

    status/
        untuk WHERE THE PROJECT IS NOW


PRINSIP HANDOVER
----------------

Dokumentasi harus memungkinkan orang atau AI lain untuk:

    membaca dokumentasi
        ↓
    memahami project
        ↓
    memahami arsitektur
        ↓
    memahami roadmap
        ↓
    mengetahui status
        ↓
    melihat Tree
        ↓
    melanjutkan pekerjaan


Dokumentasi tidak boleh bergantung pada:

- percakapan pribadi
- penjelasan lisan
- ingatan developer tertentu
- asumsi yang tidak tertulis
- konteks yang hanya diketahui oleh pembuat project


TUJUAN AKHIR
------------

Dokumentasi AI-Gabut dianggap baik apabila developer atau AI baru
dapat masuk ke project, membaca dokumentasi yang tersedia, memahami
konteks dan kondisi sistem, kemudian melanjutkan pekerjaan dengan
arah yang benar tanpa harus mengulang seluruh proses pengambilan
keputusan dari awal.
