AI-GABUT — DOCUMENTATION

Dokumentasi ini adalah sistem handover utama AI-Gabut.

VERSIONING

V1 — fase awal

Fase awal ketika AI-Gabut pertama kali dibangun. Dokumentasi lengkap V1
tidak tersedia dan tidak perlu direkonstruksi.

V2 — roadmap besar 00–13

V2 adalah fase pembangunan foundation AI-Gabut yang terdokumentasi pada
roadmap besar 00–13. Seluruh roadmap dan catatan V2 dipertahankan
sebagai sejarah dan baseline. V2 tidak dihapus atau ditimpa oleh V3.

V3 — Agentic Activation

V3 adalah fase aktif saat ini. Fokusnya adalah menghidupkan apps/agentic
menjadi aplikasi AI yang benar-benar dapat digunakan manusia.

V3 mencakup: - application runtime - identity/authentication -
multi-user isolation - sessions/chat - agent execution -
memory/context - connections - GitHub - workspace - frontend/backend
boundary - realtime/activity - approval/security/credentials -
persistence/recovery - deployment/operations - testing/validation

Multi-AI bukan scope awal V3.

STRUKTUR

    docs/
    ├── README.txt
    ├── technical/
    ├── roadmaps/
    │   ├── V3/                 # roadmap aktif
    │   └── roadmap V2/lama    # tetap dipertahankan
    └── status/

Struktur fisik repository tidak harus persis sama dengan struktur
dokumentasi. Yang wajib adalah label V2/V3 dan hubungan antar dokumen
jelas.

TECHNICAL

technical/ menjelaskan apa sistemnya dan bagaimana sistem bekerja:
architecture, boundaries, dependency, security, state, workspace,
events, API, runtime, dan deployment concepts.

ROADMAPS

roadmaps/ menjelaskan apa yang akan dibangun dan bagaimana urutannya.

V2: - roadmap besar 00–13 - roadmap detail 01–13 - dipertahankan sebagai
historical baseline

V3: - roadmaps/V3/00_Roadmap-Besar.txt adalah master roadmap aktif -
file setelahnya adalah breakdown domain - satu roadmap besar = satu
batch pembangunan - satu batch mencakup audit → boundary → contracts →
implementation → integration → reliability → validation → DoD - satu
batch menghasilkan satu delta ZIP

Roadmap adalah rencana, bukan bukti pekerjaan sudah selesai.

STATUS

status/ menjelaskan kondisi aktual: - active version - active roadmap -
current step - completed - next - blocked - validation - known gaps

Source code aktual harus diperiksa apabila dokumentasi dan implementasi
tidak cocok.

ALUR HANDOVER

    README
     ↓
    technical/
     ↓
    V2 baseline / history
     ↓
    V3 master roadmap
     ↓
    current status
     ↓
    V3 roadmap detail yang relevan
     ↓
    tree/source

ATURAN ARSITEKTUR

1.  AI-Gabut adalah platform.
2.  core/ berisi machinery generik.
3.  apps/ berisi application/product identity.
4.  connectors/ berisi adapter sistem eksternal.
5.  Core tidak bergantung pada application.
6.  Provider API tidak dipanggil langsung dari generic Agent Engine.
7.  Security adalah authority boundary.
8.  User-owned data harus terisolasi berdasarkan user identity.
9.  Credential/token bukan conversation memory.
10. Frontend tidak mengakses core secara langsung.
11. Session, memory, connection, workspace, task, execution mempunyai
    ownership yang eksplisit.
12. V2 tidak dihapus ketika V3 dimulai.
