import { runAgent } from "../agent-engine/core/agent.js";
import { resumeExecution, getReliabilityMetrics, getReliabilityLimits } from "../agent-engine/reliability/runtime.js";
import { getGovernancePolicy, issueApproval, getAuditTrail } from "../security/governance/policy.js";
import { readWorkspaceFile, writeWorkspaceFile, listWorkspaceFiles } from "../workspace/manager.js";
import { executeTerminal } from "../linux/terminal/executor.js";
import { gitStatus, gitDiff, gitChanges, gitLog } from "../linux/git/manager.js";

export function registerCoreCapabilities(registry) {
  registry
    .register("agent-engine", Object.freeze({ runAgent }), { domain: "agent-engine", type: "runtime" })
    .register("agent-reliability", Object.freeze({
      resumeExecution,
      getReliabilityMetrics,
      getReliabilityLimits
    }), { domain: "agent-engine", type: "reliability" })
    .register("security-governance", Object.freeze({
      getGovernancePolicy,
      issueApproval,
      getAuditTrail
    }), { domain: "security", type: "governance" })
    .register("workspace", Object.freeze({
      readWorkspaceFile,
      writeWorkspaceFile,
      listWorkspaceFiles
    }), { domain: "workspace", type: "workspace" })
    .register("linux-terminal", Object.freeze({ executeTerminal }), { domain: "linux", type: "terminal" })
    .register("linux-git", Object.freeze({
      gitStatus,
      gitDiff,
      gitChanges,
      gitLog
    }), { domain: "linux", type: "git" });

  return registry;
}
