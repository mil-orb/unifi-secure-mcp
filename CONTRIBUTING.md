# Contributing

Read AGENTS.md and SECURITY.md. Use synthetic network data and documentation-only identifiers. Never attach live logs, configuration, certificates, credentials, screenshots, or inventories to a change.

Install with `npm ci --ignore-scripts`. Run `npm test`, `npm run check`, `npm run privacy`, and `npm audit`. Explain what changed, the threat model impact, and the relevant validation in the pull request. Production writes are not a required test step.

Keep dependencies pinned and review lockfile changes. For a schema upgrade, obtain the official vendor specification, review changes, regenerate operation documentation, and test representative new request shapes against a simulator before choosing any operator-approved live checks. Do not silently add undocumented controller routes or generic execution tools.
