# Contributing to Foltivo Backend

Start with [the development process](docs/dev/process.md) and
[the current stack](docs/dev/stack.md). Use GitHub's Work item, Epic or Incident
report forms to propose work. Keep a work item bounded; attach code findings and
solution options during analysis. The developer selects a solution before
implementation.

Use native issue parents/dependencies and exact Type: labels. Follow the
[workflow](docs/dev/workflow.md) for branches, commit subjects, the required
**Summary** commit body and focused pull requests. Do not commit or push on the
developer's behalf without an explicit request. Record only verification actually
performed; the developer reviews and merges.

Format Go code with gofmt. Keep secrets, local configuration, build artifacts and
coverage output out of Git. Document any new configuration with placeholder-only
examples. No database, auth library or license is implied by this scaffold.

For ordinary defects, provide reproduction steps and impact. A private security
reporting channel has not been configured yet; do not put exploit details,
credentials or private user data into public issues.
