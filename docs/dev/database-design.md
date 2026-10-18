# Collaborative database design

Keep database artifacts in `database/` in this backend repository. Rust and
SeaORM replace the former Go/Ent direction; SeaORM Migration replaces Goose as
the migration executor. Automatic diagram/model/migration synchronization is deferred.

1. Inspect the current schema and identify the source commit and applied migration
   baseline represented by the design. Do not equate checked-in schema with an
   uninspected deployment.
2. Discuss proposed DBML changes through the official dbdiagram editor extension's
   local live preview. Keep proposed diagrams separate from implemented state.
   Use focused table groups when a whole-schema diagram becomes difficult to read.
3. Codex records findings and solution attachments on the owning ticket; the
   developer selects the design. Serialize developer/Codex edits to the same file.
4. Manually update SeaORM entity definitions, a new SeaORM migration when the
   physical schema changes, and the current DBML together. ORM-only mapping
   changes do not require an artificial SQL migration.
5. Record PostgreSQL details a diagram cannot express fully, including partial
   indexes, exact constraints and locking/transaction requirements, beside the
   design and migration rationale. Snapshot diagrams when useful for decisions.

Keep process instructions in `docs/dev`; diagrams belong under `database/` when
introduced by the design work. No fabricated diagrams or empty proposals are
required by the language migration. Historical proposals remain decision records;
they are not continuously updated copies of the current schema.

Visual selection does not authorize applying migrations to a database. Commits,
pushes and deployment remain separately authorized. For #18 the developer
explicitly requested implementation without reviews, validation or new tests;
record that limitation rather than claiming parity has been verified.
