import { runTool } from "../detection/index.js";
import { BrokerError } from "./errors.js";

const GIT_TIMEOUT_MS = 60_000;

/**
 * A round's commit is a machine receipt, so it carries the broker's identity
 * rather than whichever operator happened to start the run. It also means a run
 * works on a machine with no git identity configured at all.
 */
const IDENTITY = ["-c", "user.name=crossfire", "-c", "user.email=crossfire@invalid"];

async function git(repoPath: string, args: readonly string[]): Promise<string> {
  const result = await runTool("git", args, { cwd: repoPath, timeoutMs: GIT_TIMEOUT_MS });
  if (result.exitCode !== 0) {
    const detail = result.spawnError ?? result.stderr.trim();
    throw new BrokerError(
      `git ${args.join(" ")} failed in ${repoPath}: ${detail === "" ? `exit ${result.exitCode}` : detail}`,
    );
  }
  return result.stdout.trim();
}

/** Checked before the first round: a run that cannot leave commits is not a run. */
export async function assertGitRepo(repoPath: string): Promise<void> {
  const result = await runTool("git", ["rev-parse", "--git-dir"], {
    cwd: repoPath,
    timeoutMs: GIT_TIMEOUT_MS,
  });
  if (result.exitCode !== 0) {
    throw new BrokerError(
      `the target ${repoPath} is not a git repository, so a round cannot leave its commit`,
    );
  }
}

export function headSha(repoPath: string): Promise<string> {
  return git(repoPath, ["rev-parse", "HEAD"]);
}

/**
 * One commit per round, empty or not. A round that changed no code still owes
 * the ledger a git sha, and a gap in that sequence would be indistinguishable
 * from a round somebody removed.
 */
export async function commitRound(
  repoPath: string,
  message: string,
  changed: readonly string[],
): Promise<string> {
  // Only what the round said it changed. `git add -A` staged the whole worktree, so anything
  // else sitting there, a build artifact, a half-finished edit, a file written while the run
  // was still in its detection phase, landed in the round commit and was attested by the
  // ledger entry naming its sha. Rule 5 says the entry covers the round's commit, and that
  // is only true if the commit covers the round.
  //
  // An edit the report does not name is therefore not staged and does not reach the commit,
  // so the finding it was meant to close stays open into the next round. That is the
  // fail-closed direction, and it is why there is no dirty-workspace halt beside this: a
  // workspace legitimately holds files the round did not create, and refusing to commit over
  // them costs a false halt for every one.
  for (const path of [...new Set(changed)].sort()) {
    await git(repoPath, ["add", "--", path]);
  }
  await git(repoPath, [...IDENTITY, "commit", "--allow-empty", "-q", "-m", message]);
  return headSha(repoPath);
}

/** What the run has changed so far, which is the only history an agent turn gets. */
export function diffSince(repoPath: string, sha: string): Promise<string> {
  return git(repoPath, ["diff", `${sha}..HEAD`]);
}
