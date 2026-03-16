from pathlib import Path

from aidecomp_api.storage import SQLiteRepository
from aidecompd import aidecomp_runtime_pb2 as pb2
from aidecompd.server import RuntimeServicer


class DummyContext:
    def abort(self, code, detail):  # pragma: no cover - used for grpc semantics
        raise RuntimeError(f"{code}: {detail}")


def test_daemon_servicer_analyze_and_summary(tmp_path: Path) -> None:
    repo = SQLiteRepository(str(tmp_path / "daemon.db"))
    servicer = RuntimeServicer(repo)

    response = servicer.AnalyzeBinary(
        pb2.AnalyzeBinaryRequest(
            project_id="daemon-project",
            session_id="daemon-session",
            sample_id="real_pe_minimal_x64",
            binary_path="samples/real_pe/minimal_x64.exe",
        ),
        DummyContext(),
    )
    assert response.session_id == "daemon-session"

    summary = servicer.GetProgramSummary(pb2.GetProgramSummaryRequest(session_id="daemon-session"), DummyContext())
    assert "real_pe_minimal_x64" in summary.program_json
