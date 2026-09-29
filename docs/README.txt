AI-GABUT — DOCUMENTATION

Dokumentasi ini adalah sistem handover utama AI-Gabut.

VERSIONING

V1 — fase awal

Fase awal ketika AI-Gabut pertama kali dibangun. Dokumentasi lengkap V1
tidak tersedia dan tidak perlu direkonstruksi.

V2 — AI / AGENT FOUNDATION

V2 adalah foundation AI-Gabut yang terdokumentasi pada roadmap besar
00–13. V2 berisi generic AI/agent machinery, platform foundation,
security, storage, workspace, execution, synchronization, connectors,
media, API, application dan operations.

STATUS: COMPLETE terhadap roadmap V2.

V3 — AGENTIC APPLICATION + INTEGRATION FOUNDATION

V3 mengaktifkan apps/agentic sebagai application nyata di atas V2 dan
membangun integration foundation yang reusable.

V3 mencakup:
- application runtime
- identity/authentication
- multi-user isolation
- sessions/chat
- agent execution activation
- memory/context
- connections
- GitHub provider
- workspace/project context
- frontend/backend boundary
- realtime/activity
- approval/security/credentials
- persistence/recovery
- deployment/operations
- testing/validation

STATUS: COMPLETE + VALIDATED terhadap roadmap V3.

GitHub adalah salah satu provider/integration implementation. GitHub
bukan identity permanen Agentic dan tidak mendefinisikan seluruh V3.

V4 — AGENTIC WORK PLATFORM

V4 adalah fase berikutnya.

Fokusnya bukan membangun ulang V2 atau V3, tetapi menggunakan foundation
tersebut untuk membangun product/workflow layer yang memungkinkan Agent
menyelesaikan pekerjaan nyata secara observable, governed, recoverable,
dan dapat diverifikasi.

V4 mencakup:
- work/task model
- planning/execution UX
- approval/intervention UX
- workspace/diff/change experience
- verification/test loop
- autonomous repair/replan
- Git/change/PR workflow
- CI/external feedback
- long-running/background work
- recovery/resume UX
- artifacts/evidence/results
- human-agent collaboration
- work history/observability
- Agentic frontend V4
- end-to-end autonomous workflows
- testing/reliability/safety

STRUKTUR

    docs/
    ├── README.txt
    ├── technical/
    ├── roadmaps/
    │   ├── V2/                 # historical foundation baseline
    │   ├── V3/                 # completed application/integration foundation
    │   └── V4/                 # active planned work platform roadmap
    └── status/

TECHNICAL

technical/ menjelaskan apa sistemnya dan bagaimana sistem bekerja:
architecture, boundaries, dependency, security, state, workspace,
events, API, runtime, deployment, dan relationship antar version.

ROADMAPS

roadmaps/ menjelaskan apa yang akan dibangun dan bagaimana urutannya.

V2:
- roadmap besar 00–13
- historical foundation baseline

V3:
- roadmap besar 00_Roadmap-Besar.txt
- application + integration foundation
- roadmap 01–15
- status COMPLETE + VALIDATED

V4:
- 00_Roadmap-Besar.txt adalah master roadmap aktif
- file setelahnya adalah breakdown domain
- satu roadmap detail mengikuti workflow audit → boundary → contracts →
  implementation → integration → reliability → validation → DoD

Roadmap adalah rencana, bukan bukti pekerjaan sudah selesai.

STATUS

status/ menjelaskan kondisi aktual:
- active version
- completed versions
- current roadmap
- current step
- planned work
- validation
- known V4 gaps

Source code aktual harus diperiksa apabila dokumentasi dan implementasi
tidak cocok.

ARCHITECTURAL MODEL

    V2
    AI / Agent Foundation
           │
           ▼
    V3
    Agentic Application + Integration Foundation
           │
           ▼
    V4
    Agentic Work Platform

AI-Gabut adalah platform.

Application menggunakan capability platform.
Connector menyediakan interface ke external platform.
Product/use-case workflow tidak boleh dipaksakan menjadi generic core
hanya karena menjadi use-case pertama.

FRONTEND MODEL

V3 frontend adalah application client.

V4 frontend adalah work control surface.

V3:
    login → session → chat → connection → workspace → activity

V4:
    project → work → objective → plan → execution → approval →
    changes → verification → repair/replan → result → recovery

ATURAN ARSITEKTUR

1. AI-Gabut adalah platform.
2. core/ berisi machinery generik.
3. apps/ berisi application/product identity.
4. connectors/ berisi adapter sistem eksternal.
5. Core tidak bergantung pada application tertentu.
6. Provider API tidak dipanggil langsung dari generic Agent Engine.
7. Security adalah authority boundary.
8. User-owned data harus terisolasi berdasarkan user identity.
9. Credential/token bukan conversation memory.
10. Frontend tidak mengakses core secara langsung.
11. Session, memory, connection, workspace, task, execution mempunyai
    ownership yang eksplisit.
12. V2 tetap menjadi foundation historical/active platform baseline.
13. V3 tidak mengikat GitHub sebagai identity permanen Agentic.
14. V4 membangun work/product capability di atas V2 + V3.
15. Autonomous behavior harus bounded, observable, governed, dan
    recoverable.
