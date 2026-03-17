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
    assert function["ir"]["summary"]["instruction_count"] > 0
    assert function["ir"]["summary"]["memory_def_count"] >= 0
    assert function["stages"]
    assert result["stages"]

    pe_result = bridge.analyze_pe_file(sample_id="real_pe_minimal_x64", file_path="samples/real_pe/minimal_x64.exe")
    assert pe_result["arch"] == "x64"
    assert pe_result["sections"]
    assert pe_result["functions"]
    assert "xrefs" in pe_result
    first_fn = pe_result["functions"][0]
    assert "confidence" in first_fn
    assert first_fn["blocks"][0]["instructions"][0]["decode_backend"]
    assert first_fn["summary"]["return_hint"]
    assert first_fn["summary"]["maturity"]
    assert "stages" in first_fn

    constrained = bridge.analyze_pe_file(
        sample_id="real_pe_minimal_x64",
        file_path="samples/real_pe/minimal_x64.exe",
        constraints=[
            {
                "id": "py-test-no-return",
                "kind": "no_return",
                "function_name": "entry",
                "enabled": True,
            },
            {
                "id": "py-test-value-range",
                "kind": "value_range",
                "function_name": "entry",
                "variable": "edi",
                "value_text": "0..2",
                "enabled": True,
            },
            {
                "id": "py-test-type-override",
                "kind": "type_override",
                "function_name": "entry",
                "variable": "arg_0",
                "type_name": "char*",
                "enabled": True,
            },
            {
                "id": "py-test-this-pointer",
                "kind": "this_pointer",
                "function_name": "entry",
                "variable": "rcx",
                "type_name": "DemoClass*",
                "enabled": True,
            },
        ],
    )
    assert constrained["applied_constraints"]
    assert constrained["functions"][0]["summary"]["has_this_pointer"] in {True, False}

    switch_result = bridge.analyze_pe_file(
        sample_id="real_pe_switch_x64",
        file_path="samples/real_pe/switch_x64.exe",
    )
    assert switch_result["functions"]
    assert any(fn["ir"]["has_switch_candidate"] for fn in switch_result["functions"])
    assert any(fn["summary"]["possible_indirect_targets"] for fn in switch_result["functions"])
