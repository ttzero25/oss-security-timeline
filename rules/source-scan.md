# Source scan rule

Treat an external-input to dangerous-operation match as a hypothesis. Record the analyzed commit, source line, sink line, file and scan coverage. The Python scanner traces request fields, CLI input and HTTP route parameters through simple assignments. The JavaScript/TypeScript scanner uses a shallow same-file text correlation for request fields and execution calls; it does not establish a complete data flow.

Current dangerous operations include shell-enabled subprocess calls, code evaluation, Python pickle loading and URL requests. An observed pattern alone is insufficient to claim a vulnerability; inspect upstream guards, deployment defaults and the real effect before progressing.
