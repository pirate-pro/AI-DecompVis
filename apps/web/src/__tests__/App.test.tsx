import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import App from "../App";

const sampleResponse = [
  {
    sample_id: "real_pe_minimal_x64",
    arch: "x64",
    function_name: "entry",
    instruction_count: 0,
    source_type: "real_pe",
    file: "samples/real_pe/real_pe_minimal_x64.json",
    binary_file: "samples/real_pe/minimal_x64.exe"
  }
];

const analysisResponse = {
  session_id: "session-1",
  project_id: "default",
  program: {
    arch: "x64",
    sample_id: "real_pe_minimal_x64",
    image_base: 0,
    entry_point: 4096,
    sections: [{ name: ".text", va: 4096, virtual_size: 100, raw_size: 100, kind: "code" }],
    imports: [],
    exports: [],
    strings: [{ id: "str_0", va: 8192, encoding: "ascii", value: "hello" }],
    xrefs: [],
    applied_constraints: [],
    functions: [
      {
        name: "entry",
        entry_address: 4096,
        confidence: 0.9,
        entry_block_id: "B0",
        blocks: [
          {
            id: "B0",
            start_address: 4096,
            end_address: 4100,
            instructions: [
              {
                address: 4096,
                text: "push rbp",
                bytes_hex: "55",
                decode_backend: "objdump-intel",
                mnemonic: "push",
                operands: ["rbp"],
                implicit_reads: ["rsp"],
                implicit_writes: ["rsp"],
                block_id: "B0",
                has_immediate: false,
                immediate: 0,
                has_memory_operand: false,
                memory_operand: "",
                has_branch_target: false,
                branch_target: 0,
                has_call_target: false,
                call_target: 0,
                stack_effect_hint: "sp-decrease",
                stack_delta: -8,
                cumulative_stack: -8,
                is_frame_setup: true,
                is_frame_teardown: false
              }
            ],
            outgoing_edges: []
          }
        ],
        edges: [],
        stack_frame: {
          function_name: "entry",
          min_depth: -8,
          max_depth: 0,
          frame_size: 8,
          balanced: true,
          events: []
        },
        variables: [],
        stack_slots: [],
        calling_convention_hint: "x64_windows",
        params_hint: 1,
        locals_hint: 1,
        xref_in_count: 0,
        xref_out_count: 0,
        import_xref_count: 0,
        string_xref_count: 0,
        callers: [],
        callees: [],
        pseudo_code: ["B0:", "  stack_push(rbp)"],
        path_summaries: [{ block_id: "B0", path_blocks: ["B0"], summary: "Path B0" }],
        evidence_refs: [],
        called_functions: [],
        ir: {
          function_name: "entry",
          blocks: [{ id: "B0", preds: [], succs: [], instructions: [] }],
          def_use: [],
          memory_ssa: [],
          summary: {
            block_count: 1,
            instruction_count: 1,
            phi_count: 0,
            memory_def_count: 1,
            memory_use_count: 0,
            memory_phi_count: 0
          },
          has_switch_candidate: false,
          has_indirect_control: false,
          has_tailcall_candidate: false,
          unsupported_notes: []
        },
        summary: {
          return_hint: "void_or_register",
          no_return: false,
          tailcall_candidate: false,
          side_effects: [],
          imported_semantics: [],
          possible_indirect_targets: [],
          has_this_pointer: false,
          vtable_candidates: [],
          ctor_like: false,
          dtor_like: false,
          has_unwind: false,
          unwind_summary: "",
          maturity: "beta"
        },
        stages: [
          { name: "decode", status: "done", confidence: 0.9, detail: "ok" },
          { name: "lift", status: "done", confidence: 0.9, detail: "ok" }
        ],
        unwind: {
          present: false,
          begin_rva: 0,
          end_rva: 0,
          unwind_info_rva: 0,
          flags: 0,
          prolog_size: 0,
          unwind_code_count: 0,
          has_handler: false,
          note: ""
        },
        applied_constraints: []
      }
    ],
    explanations: [],
    stages: [{ name: "decode", status: "done", confidence: 0.9, detail: "ok" }],
    progress: []
  }
};

class MockEventSource {
  public onerror: ((this: EventSource, ev: Event) => unknown) | null = null;
  private listeners = new Map<string, Array<(event: MessageEvent<string>) => void>>();

  constructor(_url: string) {
    setTimeout(() => {
      this.emit("progress", {
        task_id: "task-1",
        status: "running",
        percent: 50,
        stage: "decode",
        detail: "working",
        session_id: "session-1"
      });
    }, 10);

    setTimeout(() => {
      this.emit("progress", {
        task_id: "task-1",
        status: "done",
        percent: 100,
        stage: "done",
        detail: "ok",
        session_id: "session-1"
      });
    }, 20);
  }

  addEventListener(type: string, listener: (event: MessageEvent<string>) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }

  close() {}

  private emit(type: string, payload: unknown) {
    const event = { data: JSON.stringify(payload) } as MessageEvent<string>;
    for (const handler of this.listeners.get(type) ?? []) {
      handler(event);
    }
  }
}

beforeEach(() => {
  globalThis.EventSource = MockEventSource as unknown as typeof EventSource;

  globalThis.fetch = vi.fn(async (url: string) => {
    if (url.includes("/runtime")) {
      return new Response(JSON.stringify({ mode: "embedded", daemon_target: null }), { status: 200 });
    }
    if (url.includes("/samples")) {
      return new Response(JSON.stringify(sampleResponse), { status: 200 });
    }
    if (url.includes("/discovery/binaries")) {
      return new Response(
        JSON.stringify({
          query: "",
          roots: [],
          scanned_roots: ["/home/test"],
          total: 1,
          truncated: false,
          candidates: [
            {
              path: "/home/test/build/Release/app.exe",
              name: "app.exe",
              source_root: "/home/test",
              size_bytes: 10240,
              modified_at: "2026-03-17T00:00:00Z",
              priority: 88,
              priority_label: "high",
              reasons: ["扩展名 .exe 可执行概率高"]
            }
          ]
        }),
        { status: 200 }
      );
    }
    if (url.endsWith("/projects")) {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    if (url.includes("/projects/default/state")) {
      return new Response(JSON.stringify({ project_id: "default", annotations: [], renames: [], bookmarks: [] }), {
        status: 200
      });
    }
    if (url.includes("/projects/default/ui-state")) {
      return new Response(
        JSON.stringify({ project_id: "default", current_function: "", current_block: "", beginner_mode: true }),
        {
          status: 200
        }
      );
    }
    if (url.includes("/projects/default/samples")) {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    if (url.includes("/projects/default/constraints")) {
      return new Response(JSON.stringify({ project_id: "default", constraints: [] }), { status: 200 });
    }
    if (url.includes("/analysis/tasks") && url.endsWith("/analysis/tasks")) {
      return new Response(JSON.stringify({ task_id: "task-1" }), { status: 200 });
    }
    if (url.includes("/analysis/session-")) {
      return new Response(JSON.stringify(analysisResponse), { status: 200 });
    }
    if (url.includes("/explanations")) {
      return new Response(
        JSON.stringify({
          explanation: {
            id: "exp",
            level: "function",
            confidence: 0.9,
            low_confidence: false,
            low_confidence_reason: "",
            text: "ok",
            evidence_refs: []
          }
        }),
        { status: 200 }
      );
    }
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;
});

afterEach(() => {
  vi.restoreAllMocks();
});

test("loads sample and renders function area", async () => {
  render(<App />);

  await waitFor(() => expect(screen.getByRole("button", { name: "开始分析" })).toBeInTheDocument());

  await userEvent.click(screen.getByRole("button", { name: "开始分析" }));

  await waitFor(() => expect(screen.getByText("entry")).toBeInTheDocument());
  expect(screen.getByText(/工作区与样本/i)).toBeInTheDocument();
  expect(screen.getByText(/自动扫描可反编译程序/i)).toBeInTheDocument();

  await userEvent.click(screen.getByRole("button", { name: "函数分析" }));
  expect(screen.getByText(/汇编视图/i)).toBeInTheDocument();
});
