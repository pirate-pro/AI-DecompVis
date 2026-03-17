from __future__ import annotations

import socket
from concurrent import futures
from pathlib import Path

import grpc
import pytest

from aidecomp_api.models import AnalyzeRequest
from aidecomp_api.runtime.providers.daemon import DaemonAnalysisProvider
from aidecomp_api.storage import SQLiteRepository
from aidecompd import aidecomp_runtime_pb2_grpc as pb2_grpc
from aidecompd.server import RuntimeServicer


def _free_port() -> int:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        _, port = sock.getsockname()
        sock.close()
        return int(port)
    except PermissionError:
        return -1


def test_daemon_provider_real_pe_e2e(tmp_path: Path) -> None:
    db = SQLiteRepository(str(tmp_path / "daemon-e2e.db"))
    servicer = RuntimeServicer(db)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    pb2_grpc.add_AIDecompRuntimeServicer_to_server(servicer, server)

    port = _free_port()
    if port < 0:
        pytest.skip("socket operations are restricted in this environment")
    bound = server.add_insecure_port(f"127.0.0.1:{port}")
    if bound == 0:
        pytest.skip("unable to bind grpc port in this environment")
    server.start()
    try:
        provider = DaemonAnalysisProvider(f"127.0.0.1:{port}")
        program = provider.analyze(
            AnalyzeRequest(
                project_id="daemon-e2e",
                session_id="daemon-e2e-session",
                sample_id="real_pe_minimal_x64",
                binary_path=str(Path("samples/real_pe/minimal_x64.exe").resolve()),
            )
        )
        assert program.arch == "x64"
        assert program.functions
        assert program.xrefs is not None
    finally:
        server.stop(0).wait()


def test_daemon_provider_cancelled_before_rpc() -> None:
    provider = DaemonAnalysisProvider("127.0.0.1:59999")
    with pytest.raises(RuntimeError, match="cancelled"):
        provider.analyze(
            AnalyzeRequest(
                project_id="daemon-e2e",
                session_id="cancel-before",
                sample_id="real_pe_minimal_x64",
                binary_path=str(Path("samples/real_pe/minimal_x64.exe").resolve()),
            ),
            cancelled=lambda: True,
        )
