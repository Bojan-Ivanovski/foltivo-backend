# Foltivo backend repository instructions

Read [the development process](docs/dev/process.md) before creating or updating
issues, analysing work, implementing changes or committing. Keep process docs
under docs/dev and GitHub issue forms under .github/ISSUE_TEMPLATE.

## Scope and decisions

- Use Rust for the application backend, SeaORM for database access and SeaORM Migration for schema execution; retain REST for the frontend API boundary. Backend #18 supersedes the former Go/Ent selection.
- Do not infer an auth-provider, database, deployment or collaboration protocol
  decision from the language choice. Preserve the existing frontend contracts.
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

- Follow [ticket planning](docs/dev/ticket-planning.md) for every issue: set its
  `Type:` label, assignee, Project Foltivo priority and size at creation; add
  native parent/dependency relationships; apply `Component:` only after solution
  selection and `Disposition:` when ready to close; update project status through
  analysis and delivery.
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
- All agents, including Codex and delegated agents, must do implementation work
  in a dedicated Git worktree for the issue branch. Do not implement in the
  primary checkout or share one worktree between concurrent issue work.
- First commit: Initial[#1]: <short explanation>.
- Later commits: <Issue Type>[#<issue-number>]: <short explanation>, copying the
  exact value of the issue's Type: label.
- Every commit body contains only **Summary**, a blank line and why it was done.
- Use issue branches in dedicated worktrees for subsequent implementation and
  inspect staged changes. Record delivery and verification in the PR; the
  developer merges.
- Do not add/run tests unless the developer requests testing or verification.

## Repository conventions

- Use exactly one appropriate existing Type: label. Copy its value into commit
  subjects; apply Component: labels after selecting the solution's affected areas.
- Label definitions are recorded in .github/labels.json. Preserve existing labels
  and issue assignments when synchronizing definitions.
- Follow .editorconfig and Rust formatting conventions. Keep build outputs, local
  configuration and credentials out of Git.
- Use the PR template to record changes, owning issues, performed verification
  and material risks. Do not treat template placeholders as performed checks.

## Rust migration and database ownership

- Keep the application and database Cargo crates in this repository. Do not create
  a separate backend/database repository.
- Follow docs/dev/rust-migration.md, docs/dev/database.md and
  docs/dev/database-design.md. Preserve the existing Go behavior and data formats.
- Keep all fourteen SeaORM mappings, ordered migration SQL and preserved Goose
  provenance under database/. The API never migrates automatically.
- Diagram, ORM model and migration synchronization is manual for now.
- The initial #18 implementation excluded reviews, validation and new tests. The
  developer subsequently authorized local live startup and delivery to develop.
  Basic startup/health/session observations are recorded in docs/dev/verification.md;
  do not claim full parity. Proper test coverage is separate work under #19.
  Continue to require an explicit request before adding/running tests.
