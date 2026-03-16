# AI-DecompVis Desktop MVP (Electron)

## Current capabilities

- Launches an Electron shell
- Starts local FastAPI backend automatically (embedded mode by default)
- Tries to load web UI from `http://127.0.0.1:5173`
- Falls back to built-in renderer page with local PE file picker
- Can submit selected binary path to backend `/analysis/run`

## Integration points

- `main.js`: process lifecycle + backend bootstrap
- `preload.js`: safe IPC bridge for file picking and backend URL
- `renderer/index.html`: minimal local analysis UI fallback

## Planned adapter contract

Input:
- local project id
- selected PE file path
- runtime mode (`embedded`/`daemon`)

Output:
- Program DTO from backend
- explanation payload for selected function/block/instruction

## Run

```bash
cd apps/desktop-electron
npm install
npm run dev
```

Optional env:
- `AIDECOMP_RUNTIME_MODE=daemon`
- `AIDECOMP_WEB_URL=http://127.0.0.1:5173`
