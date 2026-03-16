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
    strings: [{ va: 8192, encoding: "ascii", value: "hello" }],
    functions: [
      {
        name: "entry",
        entry_address: 4096,
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
                mnemonic: "push",
                operands: ["rbp"],
                block_id: "B0",
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
        callers: [],
        callees: [],
        pseudo_code: ["B0:", "  stack_push(rbp)"],
        path_summaries: [{ block_id: "B0", path_blocks: ["B0"], summary: "Path B0" }],
        evidence_refs: [],
        called_functions: []
      }
    ],
    explanations: [],
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
    if (url.includes("/analysis/tasks") && url.endsWith("/analysis/tasks")) {
      return new Response(JSON.stringify({ task_id: "task-1" }), { status: 200 });
    }
    if (url.includes("/analysis/session-")) {
      return new Response(JSON.stringify(analysisResponse), { status: 200 });
    }
    if (url.includes("/explanations")) {
      return new Response(
        JSON.stringify({ explanation: { id: "exp", level: "function", text: "ok", evidence_refs: [] } }),
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

  await waitFor(() => expect(screen.getByRole("button", { name: "Analyze" })).toBeInTheDocument());

  await userEvent.click(screen.getByRole("button", { name: "Analyze" }));

  await waitFor(() => expect(screen.getByText("entry")).toBeInTheDocument());
  expect(screen.getByText(/Assembly/i)).toBeInTheDocument();
  expect(screen.getByText(/Workspace \+ Program Summary/i)).toBeInTheDocument();
});
