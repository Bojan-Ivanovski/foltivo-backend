# Database artifacts

This directory is part of the backend Cargo workspace, not a separate repository.

- `src/entities.rs`: manually maintained SeaORM mappings for all fourteen tables.
- `src/lib.rs`: ordered SeaORM Migration registration.
- `migrations/`: embedded reviewed PostgreSQL up/down statements.
- `history/`: original six Goose files preserved as migration provenance.
- `proposals/`: retained issue-scoped DBML design snapshots generated from the
  committed migration baseline with `scripts/schema-proposal`.

The executable workflow and transition from Goose are documented in
[docs/dev/database.md](../docs/dev/database.md). The collaborative design process
is in [docs/dev/database-design.md](../docs/dev/database-design.md). It covers
generating a proposal with `scripts/schema-proposal` and opening it in the
interactive local viewer under [`tools/dbml-preview/`](../tools/dbml-preview/README.md).

Entity definitions do not apply schema changes. The API never runs migrations.
