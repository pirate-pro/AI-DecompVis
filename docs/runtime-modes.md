# Runtime Modes

AI-DecompVis supports `embedded` and `daemon` runtime modes.

## Embedded mode

Path:
`Web/Desktop/Plugin -> FastAPI -> pybind11 -> C++ core`

Env:
- `AIDECOMP_RUNTIME_MODE=embedded` (default)

Characteristics:
- lowest integration overhead
- easiest local debugging
- no extra gRPC hop

## Daemon mode

Path:
`Web/Desktop/Plugin -> FastAPI -> gRPC -> aidecompd -> pybind11 -> C++ core`

Env:
- `AIDECOMP_RUNTIME_MODE=daemon`
- `AIDECOMPD_TARGET=127.0.0.1:50051`

Characteristics:
- explicit runtime boundary for local agent-style deployment
- better alignment with future multi-client architecture
- better isolation of analysis process lifecycle

## Contract and compatibility

- proto: `shared/proto/aidecomp_runtime.proto`
- current API version tag: `aidecomp.runtime.v1`
- request/response include `api_version` for compatibility checks
- daemon provider validates protocol before Analyze RPC

## Cancellation path

- API endpoint: `POST /analysis/tasks/{task_id}/cancel`
- daemon provider sends `CancelAnalysis` RPC when task is cancelled while waiting
- core analysis remains synchronous; cancellation is cooperative/best-effort

## Constraint propagation

- project-level constraints are persisted in SQLite
- when analysis request has no inline constraints, FastAPI injects stored constraints
- both runtime modes forward constraints to C++ core
