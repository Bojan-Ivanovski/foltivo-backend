# Foltivo backend repository instructions

Read [the development process](docs/dev/process.md) before creating or updating
issues, analysing work, implementing changes or committing. Keep process docs
under docs/dev and GitHub issue forms under .github/ISSUE_TEMPLATE.

## Scope and decisions

- Use Go for the application backend and REST for the frontend API boundary.
- Do not infer an auth-provider, database, deployment or collaboration protocol
  decision from the choice of Go. The frontend #7 proposals need Go-aware review.
- Use `gh` with `--repo Bojan-Ivanovski/foltivo-backend`.
- Use native parent and dependency relationships. Release work defaults to backend
  epic #1 unless a delivery group or developer instruction specifies another
  parent. Do not assume frontend issue numbers identify backend issues.
- Cross-repository references must include the repository name or full URL.
- Preserve User/Organization Library ownership, optional Book references,
  independent source access and the separation of working/Git/published versions.

Read [the stack](docs/dev/stack.md), [content-model reference](docs/dev/content-model.md)
and [ticket hierarchy](docs/dev/ticket-hierarchy.md) before designing contracts.

## Issues and analysis

- Work items have exactly Summary, Scope, Analysis, Solution and Details.
- Fill Summary/Scope at creation; leave other sections pending until their stage.
- No Acceptance criteria, Implementation plan or Closeout sections.
- Codex investigates; the developer selects the solution before implementation.
- Attach findings as <N>-code-findings.md and each solution as
  <N>-solution-<k>.md using gh-attach. Verify uploads and use real attachment links.
- After selection, tag the attachment [Selected Solution] and summarize changes,
  Affected areas and Why this one in Solution.
- Details contains the findings attachment and two to four key points.

## Commits and delivery

- Wait for explicit commit or push requests; authorization is scoped to that work.
- First commit: Initial[#1]: <short explanation>.
- Later commits: <Issue Type>[#<issue-number>]: <short explanation>, copying the
  exact value of the issue's Type: label.
- Every commit body contains only **Summary**, a blank line and why it was done.
- Use issue branches for subsequent work and inspect staged changes. Record
  delivery and verification in the PR; the developer merges.
- Do not add/run tests unless the developer requests testing or verification.

## Repository conventions

- Use exactly one appropriate existing Type: label. Copy its value into commit
  subjects; apply Component: labels after selecting the solution's affected areas.
- Label definitions are recorded in .github/labels.json. Preserve existing labels
  and issue assignments when synchronizing definitions.
- Follow .editorconfig and gofmt for Go source. Keep build outputs, local
  configuration and credentials out of Git.
- Use the PR template to record changes, owning issues, performed verification
  and material risks. Do not treat template placeholders as performed checks.
