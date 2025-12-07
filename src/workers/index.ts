// src/workers/index.ts
import { Worker } from "worker_threads";
import { join } from "path";
import {
  htmlWorkerTimeout,
  htmlWorkerMaxMemoryMb,
  htmlWorkerYoungMemoryMb,
  htmlWorkerCodeRangeMb,
} from "../types.js";
import { log } from "../logging/index.js";
import { fileURLToPath } from "url";
import { dirname } from "path";

// Handle both ESM and test environments
let workersDir: string;
try {
  // @ts-ignore - import.meta.url is available in ESM
  const __filename = fileURLToPath(import.meta.url);
  workersDir = dirname(__filename);
} catch {
  // Fallback for test environment - use built workers directory
  workersDir = join(process.cwd(), "dist", "workers");
}

export interface WorkerResult<T> {
  success: boolean;
  result?: T;
  error?: string;
}

export async function runInWorker<TInput, TOutput>(
  workerPath: string,
  data: TInput,
  timeout = htmlWorkerTimeout,
): Promise<WorkerResult<TOutput>> {
  return new Promise((resolve) => {
    const worker = new Worker(join(workersDir, workerPath), {
      workerData: data,
      resourceLimits: {
        maxOldGenerationSizeMb: htmlWorkerMaxMemoryMb,
        maxYoungGenerationSizeMb: htmlWorkerYoungMemoryMb,
        codeRangeSizeMb: htmlWorkerCodeRangeMb,
      },
    });

    const timeoutId = setTimeout(() => {
      log("warn", "Worker timeout", { workerPath, timeout });
      worker.terminate();
      resolve({
        success: false,
        error: `Worker timeout after ${timeout}ms`,
      });
    }, timeout);

    worker.on("message", (result: WorkerResult<TOutput>) => {
      clearTimeout(timeoutId);
      worker.terminate();
      resolve(result);
    });

    worker.on("error", (error) => {
      log("warn", "Worker error", {
        workerPath,
        error: error.message,
        stack: error.stack,
      });
      clearTimeout(timeoutId);
      worker.terminate();
      resolve({
        success: false,
        error: error.message,
      });
    });

    worker.on("exit", (code) => {
      clearTimeout(timeoutId);
      if (code !== 0) {
        log("warn", "Worker exited with non-zero code", {
          workerPath,
          exitCode: code,
        });
        resolve({
          success: false,
          error: `Worker exited with code ${code}`,
        });
      }
    });
  });
}
