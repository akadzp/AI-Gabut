AI-GABUT — APPLICATION LAYER
============================

Folder `apps/` berisi identity dan composition application yang dibangun
di atas capability generic AI-Gabut.

ATURAN
------
- Application boleh bergantung pada core.
- Application boleh menggunakan connector.
- Core tidak boleh bergantung pada application.
- Application owns identity, domain policy, configuration, interface,
  dan deployment composition.
- Generic capability tetap berada di core.
- Provider-specific integration tetap berada di connectors.

STRUKTUR
--------
apps/
├── agentic/
├── bukaolshop-cs/
└── ...

Setiap application sebaiknya mempunyai:
- manifest
- configuration/defaults
- entry/composition point
- domain policy jika diperlukan

Jangan menaruh implementation generic core di sini.
