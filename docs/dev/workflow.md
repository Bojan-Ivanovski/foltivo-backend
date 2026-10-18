# Work workflow

Use GitHub Issues as the durable record of a change. Keep the issue body current
as the work becomes clearer; use comments for short decisions and handoffs, and
link substantial design notes or evidence instead of copying long material into
comments.

## Stages

1. **Propose.** Create a work item or epic from its issue form. Agree on the
   outcome and scope before implementation starts.
2. **Analyse and discuss.** Codex inspects the code and records factual findings,
   constraints, and compatibility concerns. Each possible solution is a separate
   Markdown attachment linked from Analysis. Codex explains the trade-offs and
   may recommend an option; the developer chooses. Leave the Solution section
   pending until that choice is made. Then mark the chosen attachment
   **[Selected Solution]** and fill Solution with the changes, affected areas,
   and reason for choosing it. Split work that cannot be reviewed as one bounded
   change into linked issues.
3. **Implement.** Work on a branch associated with the issue. Keep changes within
   its agreed scope. Update the issue when a decision changes the plan or scope.
4. **Review.** Open a pull request that links the issue (for example, `Closes
   #2`). Describe the change and verification in the pull request. Address
   review feedback before merging.
5. **Complete.** Record the delivered change and verification in the pull request.
   Link follow-up work where needed. A linked closing keyword may close the work
   item when its pull request merges.

## Branches and commits

The first repository commit is the one exception to the issue-branch workflow:
it establishes the project scaffold and its development process. Stage the
intended files explicitly, inspect the staged changes, and use a title in this
format:

```text
Initial[#<issue-number>]: <short explanation>
```

Always include a body with only a `**Summary**` heading and a short explanation
of why the change was made. The first commit uses the active release epic's
number. For example:

```markdown
**Summary**

Establish the initial Go backend and development workflow so release work can
proceed from a consistent, documented baseline.
```

After the initial commit, each work item gets its own branch from `develop` and targets `develop`. Use `<type>/<issue-number>-<short-slug>` (for example,
`feature/2-schema-migrations`). Keep one issue's work on its branch and use focused
commits with this format:

```text
<Issue Type>[#<issue-number>]: <short explanation>
```

`<Issue Type>` must exactly match the value of the issue's `Type:` label,
including capitalization and wording. For example, an issue labeled `Type: Feature`
uses `Feature[#2]: ...`; `Type: Bug` uses `Bug[#3]: ...`; and
`Type: Documentation` uses `Documentation[#4]: ...`.

Every commit body must contain only a `**Summary**` heading and a short
explanation of why the change was made.

Stage only files belonging to the change, review the staged diff before
committing, and wait for the developer to request commits and pushes. An earlier
commit or push request is not standing authorization for future work. After
pushing a commit, do not rewrite it unless the developer explicitly asks. For an
authorized rewrite, use `--force-with-lease` and stop if the remote has advanced.
The developer reviews and merges pull requests.

## Labels and project status

Labels describe work; they do not replace the issue body or project board.
Use the repository's configured labels when available. Keep label groups
independent where practical:

- **Type:** read the actual repository labels with `gh label list`; examples
  include `Type: Feature`, `Type: Bug`, and `Type: Documentation`. Use exactly one
  appropriate existing type for work items. Do not invent a substitute type.
- **Component:** apply the appropriate existing component labels after a
  solution is selected, based on the areas it affects.
- **Priority:** `Priority: High`, `Priority: Medium`, or `Priority: Low`.
- **Size:** `Size: Small`, `Size: Medium`, or `Size: Large` as a rough planning
  aid, not a promise.
- **Status:** use the project board for workflow state when one is configured;
  otherwise use `Status: Ready`, `Status: In Progress`, `Status: Blocked`, and
  `Status: In Review` consistently.

Do not invent labels when an appropriate one exists. A blocker should identify
the dependency or decision needed, with a link where possible. Remove the
blocked status once work can continue.

## Dependencies and grouped work

Place work tickets under an existing delivery group where applicable; independent
work defaults to epic #1 unless the developer specifies another parent. See
[ticket hierarchy and starting order](ticket-hierarchy.md). Pass the chosen parent with `--parent`
when creating or editing a ticket. Do not repeat the parent in
the description. Epics contain only an Objective and use the title
`<version> -- Foltivo Backend`. Track detailed work in the child issues.

Delivery-group parents are ordinary work items using the five-section template,
not additional release epics. They coordinate an outcome; implementation and
verification belong to bounded children. Preserve existing analysis and selected
solutions when regrouping. Add native blocked-by links for actual implementation
prerequisites; a shared parent does not define execution order. Analysis and UI
exploration may proceed alongside dependency work. Keep optional enhancements
from blocking the first usable slice merely because they share a parent.

## Pull requests

- Use a focused title and explain the change, rationale, and verification.
- Link the work issue with a closing keyword when merging should close it.
- Keep unrelated changes out of the pull request; create another issue when
  needed.
- Do not claim verification that was not run. List relevant checks and manual
  review plainly.
- Merge only after the required checks and review are complete.

## Blocked work

When work is blocked, update the issue with what is blocked, why, and the
specific next action or decision needed. Link the dependency or related issue.
Do not leave a vague `blocked` label without context. Resume by updating the
status and issue plan.

## Issue-specific developer instructions

Explicit developer instructions override the default workflow for that work.
For #18, the developer selected Rust, SeaORM and SeaORM Migration and requested
full parity implementation without reviews, verification or new tests. Record
that limitation honestly. It does not authorize commits, pushes, merges or
applying migrations, and it does not establish verified behavioral parity.
