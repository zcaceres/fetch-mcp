import { describe, expect, it } from "bun:test";
import { spawn } from "node:child_process";
import path from "node:path";

function runMcpSession(messages: object[]): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const serverPath = path.resolve(import.meta.dir, "index.ts");
    const proc = spawn(process.execPath, ["run", serverPath], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const responses: any[] = [];
    const expectedResponses = messages.filter((m: any) => "id" in m).length;
    let buffer = "";
    let stderr = "";

    const timeout = setTimeout(() => {
      proc.kill();
      reject(new Error(`Timed out waiting for MCP responses. stderr: ${stderr}`));
    }, 5000);

    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    proc.stdout.on("data", (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          responses.push(JSON.parse(line));
          if (responses.length >= expectedResponses) {
            clearTimeout(timeout);
            proc.kill();
            resolve(responses);
          }
        } catch (err) {
          clearTimeout(timeout);
          proc.kill();
          reject(new Error(`Failed to parse JSON-RPC line: ${line} (${err})`));
        }
      }
    });

    proc.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });

    for (const msg of messages) {
      proc.stdin.write(JSON.stringify(msg) + "\n");
    }
    proc.stdin.end();
  });
}

describe("MCP server capabilities", () => {
  it("advertises tools capability and does not advertise unimplemented resources capability", async () => {
    const responses = await runMcpSession([
      {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "test-client", version: "1.0.0" },
        },
      },
      {
        jsonrpc: "2.0",
        method: "notifications/initialized",
      },
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
      },
    ]);

    const initResp = responses.find((r) => r.id === 1);
    expect(initResp).toBeDefined();
    expect(initResp.error).toBeUndefined();
    expect(initResp.result.capabilities.tools).toBeDefined();
    expect(initResp.result.capabilities.resources).toBeUndefined();

    const toolsResp = responses.find((r) => r.id === 2);
    expect(toolsResp).toBeDefined();
    expect(toolsResp.error).toBeUndefined();
    const names = toolsResp.result.tools.map((t: any) => t.name);
    expect(names).toEqual([
      "fetch_html",
      "fetch_markdown",
      "fetch_txt",
      "fetch_json",
      "fetch_readable",
      "fetch_youtube_transcript",
    ]);
  });
});
