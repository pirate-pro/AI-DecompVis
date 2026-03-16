# VS Code Plugin MVP

## What works now

- Command: `AI-DecompVis: Connect Session`
- Reads backend session (`GET /analysis/{session_id}`)
- Shows function list in Explorer view (`AI-DecompVis Functions`)
- Command: `AI-DecompVis: Show Function Summary`
  - opens a webview with function metadata, path summary, and program summary

## Thin client boundary

The extension does **not** implement analysis logic. It only consumes backend APIs and renders host UI.

## Backend APIs used

- `GET /analysis/{session_id}`
- (indirect) function metadata/path summary from Program DTO

## Development

```bash
cd plugins/vscode
npm install
npm run build
```

Then open this folder in VS Code and press `F5` to launch Extension Development Host.

## Configuration

- `aidecompvis.backendUrl` (default `http://127.0.0.1:8000`)

## Planned next

- Tree item click -> open function CFG summary in webview
- in-editor command for selected symbol/function
- explanation panel with instruction/block/function/path tabs
