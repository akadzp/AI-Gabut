AI-GABUT / AGENTIC AI

Personal AI platform yang dikembangkan sebagai sistem AI agentic yang dapat memahami tujuan, melakukan reasoning, merencanakan pekerjaan, menggunakan tools, menjalankan task, mengelola workspace, serta terhubung dengan berbagai sistem internal dan eksternal.

Proyek ini tidak dibangun hanya sebagai chatbot.

Tujuan utamanya adalah membangun sebuah Personal AI Operating Environment yang memiliki otak agentic, kemampuan eksekusi, memory dan state, workspace, synchronization, connectors, security, serta interface yang dapat digunakan manusia untuk bekerja bersama AI.

Project Vision

AI-Gabut dirancang sebagai sistem yang memungkinkan manusia dan AI bekerja pada lingkungan yang sama.

AI tidak hanya memberikan jawaban, tetapi dapat:

memahami tujuan;

melakukan reasoning;

menyusun rencana;

memilih dan menggunakan tools;

mengerjakan task;

membaca dan mengubah workspace;

menjalankan proses secara terkontrol;

mempertahankan state dan context;

berinteraksi dengan sistem eksternal;

melakukan synchronization;

serta bekerja melalui API dan berbagai user interface.

Arsitektur proyek dibuat modular agar perkembangan satu subsystem tidak mengharuskan perubahan besar pada subsystem lainnya.

Core Principle

Prinsip utama proyek:

Agentic AI adalah salah satu product AI; intelligence engine berada di `core/agent-engine/`.

Agentic AI bertanggung jawab terhadap intelligence, reasoning, planning, decision-making, dan orchestration.

Kemampuan lain ditempatkan pada subsystem masing-masing.

Secara konseptual:

AI-GABUT │ ┌────────┴────────┐ │ Agentic AI │ │ "Brain" │ └────────┬────────┘ │ ┌──────────────┼──────────────┐ │ │ │ Storage Workspace Execution │ │ │ Sync Connectors Tasks │ │ │ Security Media API │ │ │ └──────────────┼──────────────┘ │ User / Apps 

Architecture Direction

Project dibangun dengan pemisahan subsystem yang jelas.

core/
├── platform/
├── agent-engine/
├── storage/
├── sync/
├── linux/
├── media/
├── workspace/
├── tasks/
├── security/
├── api/
└── system/

apps/
├── agentic/
└── bukaolshop-cs/

connectors/
├── browser/
├── custom/
├── github/
├── gitsync/
├── google/
├── microsoft/
└── replit/

Directory utama lainnya:

data/ runtime/ workspace/ public/ scripts/ docs/ config/ tests/

Secara umum:

AreaFungsicore/Mesin dan subsystem internal AI-Gabutapps/Identitas dan product AIconnectors/Koneksi ke sistem eksternaldata/Persistent dataruntime/Session, checkpoint, temporary runtime stateworkspace/Area kerja project dan filepublic/Public-facing assetsscripts/Development dan maintenance scriptsdocs/Dokumentasi proyekconfig/Configurationtests/Testing dan validation

Agentic AI

Agentic AI merupakan product AI yang menggunakan `core/agent-engine/` sebagai engine intelligence.

Kemampuan utamanya mencakup:

task understanding;

context management;

reasoning;

planning;

task decomposition;

execution control;

replanning;

goal management;

tool intelligence;

tool registry;

orchestration;

model routing;

reliability;

evaluation;

governance integration.

Agentic AI dirancang agar dapat menjadi pusat pengambilan keputusan dan orchestration tanpa menjadi tempat penyimpanan seluruh subsystem platform.

Multi-Model Architecture

AI-Gabut dirancang agar tidak bergantung pada satu model provider.

Model provider ditempatkan sebagai bagian dari layer model dan dapat digunakan melalui mekanisme routing.

Tujuannya adalah memungkinkan sistem menggunakan model yang berbeda berdasarkan kebutuhan task, kemampuan model, cost, latency, atau konfigurasi sistem.

Dengan pendekatan ini:

Agentic AI │ ▼ Model Router │ ├── Provider A ├── Provider B ├── Provider C └── Future Providers 

Agentic layer tidak seharusnya terikat secara langsung pada implementasi satu provider.

Workspace and Change Model

Workspace merupakan titik temu antara pekerjaan manusia dan pekerjaan AI.

Manusia dapat mengubah file.

AI juga dapat mengubah file.

Perubahan tersebut kemudian dapat diproses oleh change dan synchronization subsystem.

Secara konseptual:

Human Changes ─────┐ │ AI Changes ────────┼──► Change System ──► Sync │ External Changes ──┘ 

Dengan model ini, workspace bukan sekadar folder file, tetapi menjadi bagian dari lingkungan kerja bersama antara manusia dan AI.

Synchronization

Connector dan synchronization merupakan dua konsep berbeda.

Connector bertanggung jawab terhadap komunikasi dengan sistem eksternal.

Synchronization bertanggung jawab terhadap konsistensi perubahan antara:

local workspace;

AI changes;

human changes;

remote systems;

snapshots;

history;

conflict resolution.

Pemisahan ini penting agar connector tidak mengambil tanggung jawab yang terlalu besar dan agar mekanisme synchronization dapat berkembang secara independen.

Security

Security merupakan cross-cutting subsystem.

Agentic AI tidak seharusnya memiliki akses bebas terhadap seluruh kemampuan sistem.

Secara konseptual:

Agent │ ▼ Security Policy │ ▼ Executor / Tool │ ▼ External Effect 

Aksi dapat dibedakan berdasarkan tingkat otoritas, misalnya:

L0 Read L1 Write L2 Execute L3 External Action 

Kebijakan approval, permission, audit, dan execution control berada di bawah security architecture.

Documentation Structure

Dokumentasi proyek dipisahkan menjadi tiga lapisan utama:

docs/ ├── roadmaps/ ├── technical/ └── status/ 

Roadmaps

Menjawab:

Apa yang akan dibangun?

Roadmap menjelaskan urutan dan tujuan pengembangan setiap tahap.

Technical

Menjawab:

Bagaimana sistem dirancang dan seharusnya bekerja?

Technical documentation berisi architecture, subsystem boundaries, dependency rules, security model, data model, event system, workspace model, dan dokumentasi teknis lainnya.

Status

Menjawab:

Apa yang benar-benar sudah ada sekarang?

Status documentation berisi kondisi implementasi aktual, progress, pekerjaan yang sudah selesai, dan gap yang masih ada.

Pemisahan ini menjaga agar roadmap, desain teknis, dan kondisi aktual tidak tercampur.

Project Roadmap

Urutan utama pengembangan AI-Gabut:

00. Project Initialization 01. Agentic AI 02. Platform Foundation 03. Internal State & Storage 04. Workspace & Change System 05. Agentic ↔ Platform Integration 06. Internal Execution & Tasks 07. Synchronization 08. External Connectors 09. Media & Advanced Services 10. API & User Experience 11. Production Hardening 12. Production Release 13. Project Complete 

Detail tujuan setiap tahap terdapat pada:

docs/roadmaps/ 

Roadmap utama:

docs/roadmaps/00_Roadmap-Besar.txt 

Development Philosophy

AI-Gabut dikembangkan secara bertahap.

Setiap subsystem harus memiliki boundary yang jelas sehingga:

perubahan tidak menyebar tanpa kontrol;

dependency dapat dipahami;

subsystem dapat diuji secara independen;

implementation detail tidak mencemari architecture layer lain;

future replacement lebih mudah;

sistem dapat berkembang tanpa melakukan restructuring besar secara berulang.

Prinsip sederhananya:

Build modularly, integrate deliberately, preserve boundaries.

Current Development Direction

Project saat ini bergerak dari pembentukan Agentic AI sebagai brain menuju pembangunan platform yang menjadi lingkungan kerja bagi brain tersebut.

Artinya, pengembangan berikutnya tidak bertujuan mengganti Agentic AI yang sudah terbentuk, tetapi menyediakan platform yang dapat digunakan dan dikendalikan oleh Agentic AI secara aman dan terstruktur.

Repository Validation

Validasi dasar project dapat dijalankan dengan:

npm install npm test 

Current test/check layer digunakan untuk memastikan struktur dan syntax production backend tetap valid.

Testing behavior dan integration akan berkembang seiring bertambahnya subsystem platform.

Documentation

Dokumentasi utama:

docs/ ├── roadmaps/ │ ├── 00_Roadmap-Besar.txt │ ├── 01_Roadmap-Agentic-AI.txt │ ├── 02_Roadmap-Platform-Foundation.txt │ └── ... │ ├── technical/ │ └── ... │ └── status/ └── ... 

Mulai dari:

docs/roadmaps/00_Roadmap-Besar.txt 

untuk melihat urutan keseluruhan proyek.

Project Goal

Tujuan akhir AI-Gabut adalah membangun sebuah personal AI system yang:

Understand ↓ Reason ↓ Plan ↓ Act ↓ Observe ↓ Adapt ↓ Synchronize ↓ Continue 

AI tidak hanya menjawab pertanyaan.

AI menjadi bagian dari lingkungan kerja yang dapat memahami tujuan, menggunakan kemampuan sistem, mengerjakan pekerjaan, mempertahankan state, dan bekerja bersama manusia secara terkontrol.

Status

Untuk kondisi implementasi aktual, lihat:

docs/status/ 

Untuk desain teknis, lihat:

docs/technical/ 

Untuk urutan pengembangan, lihat:

docs/roadmaps/ 
