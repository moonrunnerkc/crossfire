import { existsSync, readdirSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";

import { toSlug } from "./identity.js";

export interface CrashFrame {
  functionName: string;
  file?: string;
  line?: number;
  module?: string;
}

export interface CrashReport {
  /** Slugged crash kind: heap-buffer-overflow, deadly-signal, segv. */
  kind: string;
  /** The reporting stack with sanitizer and fuzzer runtime frames removed. */
  frames: CrashFrame[];
  /**
   * What makes this crash that crash: the kind plus the top application frames
   * by name. Line numbers are deliberately excluded, so a patch elsewhere in
   * the function does not present the same bug as a new one. The trade is that
   * two distinct bugs in one function collapse together, which is why the raw
   * artifact is kept alongside the minimized one.
   */
  signature: string;
}

const SIGNATURE_FRAMES = 3;

const RUNTIME_MODULE = /libclang_rt|libsystem|dyld|libc\+\+abi/i;
const RUNTIME_FUNCTION = /^(fuzzer::|__asan|__sanitizer|__lsan|__ubsan|__tsan|wrap_|main$|start$)/;
const RUNTIME_FILE = /(^|[/\\])(Fuzzer[A-Za-z]*\.cpp|(asan|sanitizer|lsan|ubsan)_[a-z_]*\.cpp)$/;

function crashKind(stderr: string): string | undefined {
  const sanitizer = /ERROR:\s+\w*Sanitizer:\s+([A-Za-z-]+)/.exec(stderr);
  if (sanitizer?.[1] !== undefined) {
    return toSlug(sanitizer[1]);
  }
  const libfuzzer = /ERROR:\s+libFuzzer:\s+(deadly signal|out-of-memory|timeout|[a-z-]+)/i.exec(
    stderr,
  );
  if (libfuzzer?.[1] !== undefined) {
    return toSlug(libfuzzer[1]);
  }
  const summary = /SUMMARY:\s+\w*Sanitizer:\s+([A-Za-z-]+)/.exec(stderr);
  return summary?.[1] === undefined ? undefined : toSlug(summary[1]);
}

function parseFrame(body: string): CrashFrame {
  const inModule = /^(.*?)\s+\(([^)]+)\)$/.exec(body);
  if (inModule?.[1] !== undefined && inModule[2] !== undefined) {
    return { functionName: stripOffset(inModule[1]), module: inModule[2] };
  }

  const located = /^(.*?)\s+(\S+):(\d+)(?::\d+)?$/.exec(body);
  if (located?.[1] !== undefined && located[2] !== undefined && located[3] !== undefined) {
    return {
      functionName: stripOffset(located[1]),
      file: located[2],
      line: Number.parseInt(located[3], 10),
    };
  }

  return { functionName: stripOffset(body) };
}

function stripOffset(functionName: string): string {
  return functionName.replace(/\+0x[0-9a-f]+$/i, "").trim();
}

function isRuntimeFrame(frame: CrashFrame): boolean {
  if (frame.module !== undefined && RUNTIME_MODULE.test(frame.module)) {
    return true;
  }
  if (RUNTIME_FUNCTION.test(frame.functionName)) {
    return true;
  }
  return frame.file !== undefined && RUNTIME_FILE.test(frame.file);
}

/**
 * Reads the first stack in a sanitizer report. Later stacks ("allocated by
 * thread T0 here") describe context, not the failure, so frame numbering
 * restarting at #0 ends the parse.
 */
function parseFrames(stderr: string): CrashFrame[] {
  const frames: CrashFrame[] = [];
  let started = false;

  for (const line of stderr.split("\n")) {
    const match = /^\s*#(\d+)\s+0x[0-9a-f]+\s+(?:in\s+)?(.+?)\s*$/.exec(line);
    if (match?.[1] === undefined || match[2] === undefined) {
      continue;
    }
    const index = Number.parseInt(match[1], 10);
    if (index === 0) {
      if (started) {
        break;
      }
      started = true;
    }
    if (!started) {
      continue;
    }
    frames.push(parseFrame(match[2]));
  }

  return frames;
}

export function parseCrashReport(stderr: string): CrashReport | undefined {
  const kind = crashKind(stderr);
  if (kind === undefined) {
    return undefined;
  }

  const allFrames = parseFrames(stderr);
  const appFrames = allFrames.filter((frame) => !isRuntimeFrame(frame));
  // A stripped or fully inlined binary can leave nothing but runtime frames.
  // Signing over the raw stack still beats signing over the kind alone.
  const frames = appFrames.length > 0 ? appFrames : allFrames;
  const signature = [kind, ...frames.slice(0, SIGNATURE_FRAMES).map((f) => f.functionName)].join(
    "|",
  );

  return { kind, frames, signature };
}

/**
 * Turns the path a sanitizer printed into a repo relative one. macOS symbolizes
 * through atos by default and prints bare basenames, so a basename that matches
 * exactly one in-scope file is resolved against the tree.
 */
export function resolveRepoFile(
  candidate: string,
  repoPath: string,
  inScopeDirs: readonly string[],
): string | undefined {
  if (isAbsolute(candidate)) {
    const rel = relative(repoPath, candidate);
    return rel.startsWith("..") ? undefined : toPosix(rel);
  }

  if (existsSync(resolve(repoPath, candidate))) {
    return toPosix(candidate);
  }

  const matches = inScopeDirs
    .flatMap((dir) => listFiles(resolve(repoPath, dir), repoPath))
    .filter((file) => file === candidate || file.endsWith(`/${candidate}`));

  return matches.length === 1 ? matches[0] : undefined;
}

function toPosix(path: string): string {
  return path.split("\\").join("/");
}

function listFiles(dir: string, repoPath: string): string[] {
  if (!existsSync(dir)) {
    return [];
  }
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => toPosix(relative(repoPath, join(entry.parentPath, entry.name))));
}
