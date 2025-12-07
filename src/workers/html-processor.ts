// src/workers/html-processor.ts
import { parentPort, workerData } from "worker_threads";
import { JSDOM } from "jsdom";
import TurndownService from "turndown";

export interface WorkerInput {
  html: string;
  mode: "text" | "markdown";
}

export interface WorkerOutput {
  success: boolean;
  result?: string;
  error?: string;
}

function processHtml(input: WorkerInput): WorkerOutput {
  try {
    const dom = new JSDOM(input.html);
    const document = dom.window.document;

    // Remove scripts and styles
    const scripts = document.getElementsByTagName("script");
    const styles = document.getElementsByTagName("style");
    Array.from(scripts).forEach((script) => script.remove());
    Array.from(styles).forEach((style) => style.remove());

    let result: string;

    if (input.mode === "text") {
      const text = document.body.textContent || "";
      result = text.replace(/\s+/g, " ").trim();
    } else {
      const turndownService = new TurndownService();
      result = turndownService.turndown(input.html);
    }

    return { success: true, result };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

// Worker entry point
if (parentPort) {
  const input = workerData as WorkerInput;
  const output = processHtml(input);
  parentPort.postMessage(output);
}

export { processHtml };
