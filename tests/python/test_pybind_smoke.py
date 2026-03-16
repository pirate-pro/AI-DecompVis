from aidecomp_py import CoreBridge


def test_pybind_smoke_demo_analysis() -> None:
    bridge = CoreBridge()
    instructions = bridge.demo_instructions()
    result = bridge.analyze_sequence(
        arch="x64",
        sample_id="demo_stack_branch",
        function_name="demo_main",
        instructions=instructions,
    )

    assert result["arch"] == "x64"
    assert result["functions"]

    function = result["functions"][0]
    assert len(function["blocks"]) >= 3
    assert function["stack_frame"]["frame_size"] >= 32

    pe_result = bridge.analyze_pe_file(sample_id="real_pe_minimal_x64", file_path="samples/real_pe/minimal_x64.exe")
    assert pe_result["arch"] == "x64"
    assert pe_result["sections"]
    assert pe_result["functions"]
