# Local DBML preview

Interactive, dark-mode viewer for a DBML proposal, built with
[`dbml-erd-viewer`](https://github.com/usingsky/dbml-erd-viewer). It reads the
selected DBML file through a symlink in `public/schema.dbml`; the preview does
not change database migrations or the proposal itself. Drag tables to arrange
them, use automatic layout to reorganize the diagram, and reset saved positions
with **Reset layout**. Table positions are saved in browser local storage.

Requires Node.js `^20.19.0` or `>=22.12.0` (required by Vite 8).

## Start

From the backend repository root, generate a proposal from committed
migrations. Use a unique issue number and proposal name; the command refuses to
overwrite an existing file:

```sh
scripts/schema-proposal 21-my-proposal
```

This creates `database/proposals/21-my-proposal.dbml`. Install the viewer
dependencies once and start the preview:

```sh
cd tools/dbml-preview
npm install
npm start -- database/proposals/21-my-proposal.dbml
```

Open <http://localhost:4173>. To preview another proposal, pass its path after
`npm start --`. Relative paths are resolved from the repository root; absolute
paths are accepted too. Press **Ctrl+C** in the terminal to stop the server.

The preview uses a local symlink to read the DBML source. The **View DBML
source** link opens that file in the browser. Edit the DBML file in your editor,
then click **Reload DBML** to render its changes. Use **Reset layout** to clear
saved table positions and apply the automatic layout again. These visual edits
do not alter the DBML, SeaORM entities, or migrations.
