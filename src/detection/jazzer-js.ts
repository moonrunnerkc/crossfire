import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { Severity } from "../contracts/index.js";
import type { CrashFrame, CrashReport } from "./crash-report.js";
import { crashReportOf, frameLine, toPosix } from "./crash-report.js";
import { shellQuote } from "./exec.js";
import { toSlug } from "./identity.js";
import type { EngineCommand, LibFuzzerTarget } from "./libfuzzer-driver.js";
import {
  INPUT_TIMEOUT_SECONDS,
  MINIMIZE_CRASH_FLAG,
  libFuzzerDriver,
} from "./libfuzzer-driver.js";
import type { FuzzEngine, FuzzJob } from "./types.js";

/** Installed by @jazzer.js/core, next to the harness it fuzzes. */
const JAZZER_BIN = "node_modules/.bin/jazzer";

/**
 * Jazzer.js reports its own bug detectors by name rather than as an uncaught
 * exception. Everything it does not name is an uncaught exception, and takes
 * the driver's default severity.
 */
const SEVERITY_BY_KIND: Record<string, Severity> = {
  "command-injection": "critical",
  "remote-code-execution": "critical",
  "prototype-pollution": "high",
  "path-traversal": "high",
  "server-side-request-forgery-ssrf": "high",
  "segmentation-fault": "high",
  "out-of-memory": "medium",
  timeout: "medium",
};

export function createJazzerJsEngine(): FuzzEngine {
  return libFuzzerDriver(JAZZER_JS);
}

const JAZZER_JS: LibFuzzerTarget = {
  id: "jazzer.js",

  unrunnable(job: FuzzJob): string | undefined {
    if (!existsSync(resolve(job.scope.repoPath, job.harness.entryPoint))) {
      return `harness module ${job.harness.entryPoint} does not exist`;
    }
    if (!existsSync(jazzerOf(job))) {
      return `${JAZZER_BIN} is missing, so the target has no Jazzer.js to run the ${job.harness.id} harness with`;
    }
    return undefined;
  },

  /**
   * Jazzer.js takes its own options before the `--` and hands everything after
   * it to libFuzzer. Its `--timeout` wins over libFuzzer's `-timeout`, so the
   * per input ceiling is set here in milliseconds rather than passed through.
   */
  command(job: FuzzJob, flags: readonly string[], inputs: readonly string[]): EngineCommand {
    return {
      file: jazzerOf(job),
      args: [
        toPosix(job.harness.entryPoint),
        ...inputs,
        "--timeout",
        String(INPUT_TIMEOUT_SECONDS * 1000),
        // Minimization is the one invocation that has to run synchronously.
        // Asynchronously, Jazzer.js exits its own process between minimizer
        // steps, libFuzzer reports that exit as a crash of its own, and the
        // unit in flight is written over the minimized artifact. A harness
        // that genuinely is asynchronous fails this run rather than producing
        // a wrong artifact, and the driver ships the raw input instead.
        ...(flags.includes(MINIMIZE_CRASH_FLAG) ? ["--sync"] : []),
        ...(flags.length === 0 ? [] : ["--", ...flags]),
      ],
    };
  },

  parseReport: parseJazzerReport,

  severityByKind: SEVERITY_BY_KIND,

  reproCommand(job: FuzzJob, artifactRel: string): string {
    return [
      "!",
      shellQuote(`./${JAZZER_BIN}`),
      shellQuote(toPosix(job.harness.entryPoint)),
      shellQuote(artifactRel),
      "--timeout",
      String(INPUT_TIMEOUT_SECONDS * 1000),
    ].join(" ");
  },
};

function jazzerOf(job: FuzzJob): string {
  return resolve(job.scope.repoPath, JAZZER_BIN);
}

const ENGINE_ERROR =
  /^==\d+==\s*ERROR:\s+libFuzzer:\s+(deadly signal|out-of-memory|timeout|[a-z-]+)/im;
const UNCAUGHT = /^==\d+==\s*Uncaught Exception:\s*(.*)$/m;
const REPORTED = /^==\d+==\s*(.*)$/m;
/** `TypeError: message`, the header V8 puts on a thrown Error. */
const ERROR_HEADER = /^([A-Za-z_$][\w$]*)\s*:/;
/** A bug detector names its bug in a few words. Longer is not a bug class. */
const MAX_REPORTED_KIND = 64;

export function parseJazzerReport(stderr: string): CrashReport | undefined {
  const kind = crashKind(stderr);
  if (kind === undefined) {
    return undefined;
  }
  return crashReportOf(kind, parseFrames(stderr), isRuntimeFrame);
}

/**
 * Jazzer.js prints one `==<pid>== ` line naming the failure. There are three
 * shapes of it: libFuzzer's own errors, which it passes through; an uncaught
 * exception, which it prefixes as one; and one of its own bug detectors, which
 * prints the finding's message with no prefix at all.
 */
function crashKind(stderr: string): string | undefined {
  const engineError = ENGINE_ERROR.exec(stderr);
  if (engineError?.[1] !== undefined) {
    return toSlug(engineError[1]);
  }

  const uncaught = UNCAUGHT.exec(stderr);
  if (uncaught?.[1] !== undefined) {
    // A thrown Error carries its class in the header. Anything else, a thrown
    // string among them, only says that something escaped the harness.
    const header = ERROR_HEADER.exec(uncaught[1].trim());
    return header?.[1] === undefined ? "uncaught-exception" : toSlug(header[1]);
  }

  // A bug detector finding, whose message opens by naming the bug class:
  // "Command Injection", "Prototype Pollution". This is the one shape a target
  // could forge by printing to its own stderr, so it is the one that is bounded:
  // libFuzzer's own status lines carry the same pid prefix, and anything too
  // long to be a bug class is an unreadable report rather than a new one.
  const reported = REPORTED.exec(stderr)?.[1]?.trim();
  if (
    reported === undefined ||
    reported === "" ||
    reported.length > MAX_REPORTED_KIND ||
    /libFuzzer:/i.test(reported)
  ) {
    return undefined;
  }
  return toSlug(reported);
}

const FRAME_LINE = /^\s+at\s+(.+?)\s*$/;

/**
 * The stack V8 printed, up to the first line that is not a frame. Jazzer.js has
 * already dropped its own frames by the time it prints, so what is left is the
 * harness and the target.
 */
function parseFrames(stderr: string): CrashFrame[] {
  const frames: CrashFrame[] = [];
  let started = false;

  for (const line of stderr.split("\n")) {
    const match = FRAME_LINE.exec(line);
    if (match?.[1] === undefined) {
      if (started) {
        break;
      }
      continue;
    }
    started = true;
    frames.push(parseFrame(match[1]));
  }

  return frames;
}

/** `name (file:line:column)`, or a bare `file:line:column` when anonymous. */
function parseFrame(body: string): CrashFrame {
  const named = /^(.+?)\s+\((.+)\)$/.exec(body);
  const located = /^(.+):(\d+):(\d+)$/.exec(named?.[2] ?? body);

  if (located?.[1] === undefined || located[2] === undefined) {
    // A native frame, "at Array.map (<anonymous>)": it names a frame but no
    // file, and the frames underneath it still matter.
    return { functionName: named?.[1] ?? body };
  }
  const line = frameLine(located[2]);
  return {
    functionName: named?.[1] ?? "<anonymous>",
    file: toFilePath(located[1]),
    ...(line === undefined ? {} : { line }),
  };
}

/** Frames from a module loaded as ESM are printed as file:// URLs. */
function toFilePath(location: string): string {
  if (!location.startsWith("file://")) {
    return location;
  }
  try {
    return fileURLToPath(location);
  } catch {
    // A malformed URL is still worth keeping as text: it names the frame even
    // when it cannot name a file on disk.
    return location;
  }
}

function isRuntimeFrame(frame: CrashFrame): boolean {
  if (frame.file === undefined) {
    return false;
  }
  return frame.file.startsWith("node:") || toPosix(frame.file).includes("/node_modules/");
}
