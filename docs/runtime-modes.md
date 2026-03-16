# Runtime Modes

AI-DecompVis supports two runtime modes:

## 1) embedded mode

Path:
`Web/Desktop/Plugin -> FastAPI -> pybind11 -> C++ core`

Use when:
- local single-user workflow
- fast setup
- easiest debugging

Env:
- `AIDECOMP_RUNTIME_MODE=embedded`

## 2) daemon mode

Path:
`Web/Desktop/Plugin -> FastAPI -> gRPC -> aidecompd -> C++ core`

Use when:
- isolate analysis runtime
- prepare future multi-client local architecture
- align with plugin thin-client boundary

Env:
- `AIDECOMP_RUNTIME_MODE=daemon`
- `AIDECOMPD_TARGET=127.0.0.1:50051`

Run daemon:

```bash
PYTHONPATH=core/aidecomp_py/python:services/aidecomp_api:services \
  .venv/bin/python -m aidecompd.main
```

Then run API in daemon mode:

```bash
AIDECOMP_RUNTIME_MODE=daemon AIDECOMPD_TARGET=127.0.0.1:50051 \
PYTHONPATH=core/aidecomp_py/python:services/aidecomp_api:services \
  .venv/bin/uvicorn aidecomp_api.main:app --app-dir services/aidecomp_api --host 127.0.0.1 --port 8000
```
