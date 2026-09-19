# Central aggregation

Central aggregation is optional and must never be required for local research to complete. An upload failure may be recorded as synchronization status, but it must not change a candidate, PoC, evidence-gate, or disclosure verdict.

Bundles contain only normalized public identifiers, timestamps, run states, and one-way candidate identifiers. They must not contain source snippets, source or evidence paths, checkout locations, PoC bodies or output, claims, disclosure drafts, submission references, API credentials, or user identity. Bundled self-test repositories and their related entities are excluded from export.

Ingestion is bearer-token authenticated, size bounded, schema validated, integrity checked, and idempotent by content-derived bundle ID. Entity counts are deduplicated by stable keys rather than added from client totals. CVE, GHSA, and source advisory aliases are merged before counting. The public statistics endpoint returns totals only.

The bundled HTTP collector is an application server, not a TLS endpoint. Bind it to a private interface or loopback and place it behind an HTTPS reverse proxy with operational rate limits, request logging policy, backups, and token rotation before team use.
