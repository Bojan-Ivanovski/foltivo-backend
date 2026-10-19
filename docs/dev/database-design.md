# Collaborative database design

Keep database artifacts in `database/` in this backend repository. Rust and
SeaORM replace the former Go/Ent direction; SeaORM Migration replaces Goose as
the migration executor. Automatic diagram/model/migration synchronization is deferred.

1. Commit migration changes before generating a proposal. From the backend root,
   run the generator with a unique issue-scoped name:

   ```sh
   scripts/schema-proposal 21-new-proposal
   ```

   The command starts a temporary PostgreSQL container without a persistent
   volume, applies the committed SeaORM migrations, exports the schema to
   `database/proposals/21-new-proposal.dbml`, and removes the container.
   It does not read `.env` or connect to the Compose, development, or production
   database. It requires Docker, Rust/Cargo, OpenSSL, Node.js 18 or newer, and
   the DBML CLI. Install it in the user-local prefix and add its bin directory
   to `PATH`:

   ```sh
   npm install --global --prefix "$HOME/.local" @dbml/cli
   export PATH="$HOME/.local/bin:$PATH"
   ```
2. Open the generated proposal in the interactive, dark-mode viewer under
   `tools/dbml-preview/`. Install viewer dependencies once, then start it with
   the generated file:

   ```sh
   cd tools/dbml-preview
   npm install
   npm start -- database/proposals/21-new-proposal.dbml
   ```

   Open `http://localhost:4173`. The preview reads the selected proposal via a
   local symlink and does not modify the DBML. Drag tables to arrange them, use
   automatic layout as needed, and click **Reset layout** to clear saved table
   positions. After editing the DBML in your editor, click **Reload DBML**.
   **View DBML source** opens the selected source file. Stop the server with
   Ctrl+C. The viewer requires Node.js `^20.19.0` or `>=22.12.0`; see
   [`tools/dbml-preview/README.md`](../../tools/dbml-preview/README.md) for
   complete usage. Retain each proposal as its own issue-scoped snapshot. The
   generator refuses to overwrite an existing proposal. Generate the next
   proposal from the latest committed migration baseline; do not maintain a
   separate canonical current-state DBML file. The exported `seaql_migrations`
   table is SeaORM bookkeeping, not a product entity.
3. Codex records findings and solution attachments on the owning ticket; the
   developer selects the design. Serialize developer/Codex edits to the same
   proposal file.
4. After approval, manually update SeaORM entity definitions and add a new
   SeaORM migration when physical schema changes. The migration SQL remains the
   authority; ORM-only mapping changes do not require an artificial SQL
   migration. Keep the proposal snapshot as the design record.
5. Record PostgreSQL details a diagram cannot express fully, including partial
   indexes, exact constraints and locking/transaction requirements, beside the
   proposal and migration rationale.

Keep process instructions in `docs/dev`; generated design proposals belong under
`database/proposals/`. Proposal files are versioned snapshots of a particular
migration baseline, not continuously updated copies of the current schema. The
script's PostgreSQL image digest must stay aligned with the pinned image in
`compose.yaml`.

The generator applies committed migrations only to its own disposable database.
Visual design selection does not authorize applying proposed migrations to a
developer, shared, or deployed database. Commits, pushes and deployment remain
separately authorized. For #18 the developer explicitly requested implementation
without reviews, validation or new tests; record that limitation rather than
claiming parity has been verified.
