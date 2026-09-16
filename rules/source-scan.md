# Source scan rule

Treat an external-input to dangerous-operation match as a hypothesis. Record the analyzed commit, stable tracking ID, source and sink files, every cited call hop, and scan coverage. The Python scanner traces request fields, CLI input and HTTP route parameters through simple assignments and bounded cross-module function or statically resolvable instance-method calls. A module-level literal mapping assigned once and never mutated is treated as a fixed allowlist boundary; mutated mappings remain tainted. The JavaScript/TypeScript scanner uses a shallow same-file text correlation for request fields and execution calls; it does not establish a complete data flow.

Current dangerous operations include shell-enabled subprocess calls, code evaluation, Python pickle loading and URL requests. An observed pattern alone is insufficient to claim a vulnerability; inspect upstream guards, deployment defaults and the real effect before progressing.
