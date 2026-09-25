import {
  gitStatus,
  gitChanges,
  gitDiff,
  gitLog,
  gitAdd,
  gitCommit,
  gitPush,
  gitUnstagedAndStagedDiff
} from "../../linux/git/manager.js";

export async function runGitTool(action, input = {}) {
  switch (action) {
    case "status": return gitStatus();
    case "changes": return gitChanges();
    case "diff": return gitDiff({ staged: Boolean(input.staged) });
    case "diff_all": return gitUnstagedAndStagedDiff();
    case "log": return gitLog({ limit: input.limit });
    case "add": return gitAdd({ paths: input.paths });
    case "commit": return gitCommit({ message: input.message });
    case "push": return gitPush({ remote: input.remote || "origin", branch: input.branch || "" });
    default: throw new Error(`Git action tidak dikenal: ${action}`);
  }
}
