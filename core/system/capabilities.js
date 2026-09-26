import { runAgent } from "../agent-engine/core/agent.js";
import { resumeExecution, getReliabilityMetrics, getReliabilityLimits } from "../agent-engine/reliability/runtime.js";
import { getGovernancePolicy, issueApproval, getAuditTrail, getAuditMetrics, getAuditPolicy } from "../security/index.js";
import { readWorkspaceFile, writeWorkspaceFile, listWorkspaceFiles, createWorkspaceChangeSystem, workspaceChangeSystem } from "../workspace/index.js";
import { createTaskOrchestrator, taskOrchestrator } from "../tasks/index.js";
import { executeTerminal } from "../linux/terminal/executor.js";
import { gitStatus, gitDiff, gitChanges, gitLog } from "../linux/git/manager.js";
import { getEnvironmentSnapshot, getSystemInfo, getResourceSnapshot, getCurrentProcessInfo, isProcessAlive, statWorkspacePath, listWorkspaceDirectory, detectPackageManagers, readPackageManifest, getServiceManager } from "../linux/index.js";

export function registerCoreCapabilities(registry) {
  registry
    .register("agent-engine", Object.freeze({ runAgent }), { domain: "agent-engine", type: "runtime" })
    .register("agent-reliability", Object.freeze({ resumeExecution, getReliabilityMetrics, getReliabilityLimits }), { domain: "agent-engine", type: "reliability" })
    .register("security-governance", Object.freeze({ getGovernancePolicy, issueApproval, getAuditTrail, getAuditMetrics, getAuditPolicy }), { domain: "security", type: "governance" })
    .register("workspace", Object.freeze({ readWorkspaceFile, writeWorkspaceFile, listWorkspaceFiles }), { domain: "workspace", type: "workspace" })
    .register("workspace-change-system", Object.freeze({ createWorkspaceChangeSystem, workspaceChangeSystem }), { domain: "workspace", type: "change-system" })
    .register("task-orchestration", Object.freeze({ createTaskOrchestrator, taskOrchestrator }), { domain: "tasks", type: "orchestration" })
    .register("linux-terminal", Object.freeze({ executeTerminal }), { domain: "linux", type: "terminal" })
    .register("linux-git", Object.freeze({ gitStatus, gitDiff, gitChanges, gitLog }), { domain: "linux", type: "git" })
    .register("linux-local-system", Object.freeze({ getEnvironmentSnapshot, getSystemInfo, getResourceSnapshot, getCurrentProcessInfo, isProcessAlive, statWorkspacePath, listWorkspaceDirectory, detectPackageManagers, readPackageManifest, getServiceManager }), { domain: "linux", type: "local-system" });
  return registry;
}
