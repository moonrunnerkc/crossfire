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

/**
 * Assembles a report from a parsed stack, with the reporting runtime's own
 * frames dropped so the signature is about the target. A stripped binary, or a
 * stack that is all runtime, can leave nothing behind: signing over the raw
 * stack still beats signing over the kind alone.
 */
export function crashReportOf(
  kind: string,
  stack: readonly CrashFrame[],
  isRuntimeFrame: (frame: CrashFrame) => boolean,
): CrashReport {
  const appFrames = stack.filter((frame) => !isRuntimeFrame(frame));
  const frames = appFrames.length > 0 ? appFrames : [...stack];
  const signature = [
    kind,
    ...frames.slice(0, SIGNATURE_FRAMES).map((frame) => frame.functionName),
  ].join("|");
  return { kind, frames, signature };
}

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
    return { functionName: frameName(inModule[1]), module: inModule[2] };
  }

  const located = /^(.*?)\s+(\S+):(\d+)(?::\d+)?$/.exec(body);
  if (located?.[1] !== undefined && located[2] !== undefined && located[3] !== undefined) {
    const line = frameLine(located[3]);
    return {
      functionName: frameName(located[1]),
      file: located[2],
      ...(line === undefined ? {} : { line }),
    };
  }

  return { functionName: frameName(body) };
}

/**
 * A frame's line number, or undefined when what the tool printed is not one.
 * A Finding's line has to be a positive integer, and a symbolizer with no line
 * information to give prints 0 rather than leaving the field out.
 */
export function frameLine(text: string): number | undefined {
  const line = Number.parseInt(text, 10);
  return Number.isSafeInteger(line) && line > 0 ? line : undefined;
}

/**
 * The frame's name with the offset the symbolizer appended taken off. A frame
 * in a stripped module has nothing left after that, and an unnamed frame in a
 * signature would quietly collapse two different stacks into one, so it says
 * what it is instead.
 */
function frameName(functionName: string): string {
  return functionName.replace(/\+0x[0-9a-f]+$/i, "").trim() || "<unknown>";
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

  return crashReportOf(kind, parseFrames(stderr), isRuntimeFrame);
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

/** Repo relative paths are posix in findings, whatever the host separator is. */
export function toPosix(path: string): string {
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
