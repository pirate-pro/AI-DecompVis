# VS Code Plugin MVP (P4/P5)

## What works now

- Connect backend session in 2 ways:
  - `AI-DecompVis: Connect Session` (manual session id)
  - `AI-DecompVis: Select Project Session` (project -> session quick pick)
- Function tree in Explorer (`AI-DecompVis Functions`) with filtering:
  - `AI-DecompVis: Search Functions`
- Function drill-down:
  - click tree item or run `AI-DecompVis: Show Function Summary`
- Explanation workflow:
  - `AI-DecompVis: Show Explanation`
  - supports instruction/block/function/path level request
  - renders confidence + evidence in webview
- Write-back workflow:
  - `AI-DecompVis: Add Annotation`
  - `AI-DecompVis: Add Bookmark`
- User-guided reanalysis:
  - `AI-DecompVis: Apply No-Return Constraint`
  - `AI-DecompVis: Apply Value-Range Constraint`
  - `AI-DecompVis: Apply Type-Override Constraint`
  - plugin 会触发后端重分析并刷新当前 session

## Thin client boundary

The extension does **not** implement analysis logic. It only consumes backend APIs and renders host UI.

## Backend APIs used

- `GET /projects`
- `GET /projects/{project_id}/sessions`
- `GET /analysis/{session_id}`
- `POST /explanations`
- `POST /projects/{project_id}/annotations`
- `POST /projects/{project_id}/bookmarks`
- `POST /projects/{project_id}/constraints`
- `POST /analysis/run`

## Development

```bash
cd plugins/vscode
npm install
npm run build
```

Then open this folder in VS Code and press `F5` to launch Extension Development Host.

## Configuration

- `aidecompvis.backendUrl` (default `http://127.0.0.1:8000`)

## End-to-end plugin workflow

1. Start backend (embedded or daemon mode).
2. Run analysis in Web/Desktop once to create project/session.
3. In VS Code extension host, execute `AI-DecompVis: Select Project Session`.
4. Select function from tree and open summary.
5. Run `AI-DecompVis: Show Explanation` for instruction/block/function/path.
6. Run `AI-DecompVis: Add Annotation` / `AI-DecompVis: Add Bookmark` to write back.
