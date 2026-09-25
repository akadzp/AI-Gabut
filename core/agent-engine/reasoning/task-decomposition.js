const MAX_TEXT = 12000;
const MAX_STEPS = 12;

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function normalizeFiles(files = []) {
  return unique(files.map(value => String(value || '').trim())).slice(0, 40);
}

function step(id, title, purpose, dependsOn = []) {
  return { id, title, purpose, dependsOn };
}

export function decomposeTask({ prompt = "", understanding = null, conversation = [] } = {}) {
  const text = String(prompt || understanding?.goal || "").trim().slice(0, MAX_TEXT);
  const taskType = understanding?.taskType || "general";
  const actions = Array.isArray(understanding?.actions) ? unique(understanding.actions) : [];
  const files = normalizeFiles(understanding?.targets?.files || []);
  const constraints = unique(understanding?.constraints || []);
  const ambiguity = unique(understanding?.ambiguity || []);
  const steps = [];

  steps.push(step("understand", "Confirm task scope", "Use the task representation, conversation context, and explicit constraints as the initial scope."));

  if (ambiguity.length) {
    steps.push(step("resolve-ambiguity", "Resolve material ambiguity", "Identify missing targets, references, or constraints before taking a consequential action.", ["understand"]));
  }

  const inspectDepends = ambiguity.length ? ["resolve-ambiguity"] : ["understand"];
  if (taskType !== "explanation" || actions.some(action => ["inspect", "edit", "create", "delete", "migrate", "review", "test"].includes(action))) {
    steps.push(step("inspect", "Inspect relevant workspace evidence", "Read only the project files, symbols, contracts, schemas, or configuration needed to understand the requested work.", inspectDepends));
  }

  if (actions.includes("edit") || actions.includes("create") || actions.includes("delete") || taskType === "migration") {
    steps.push(step("impact", "Assess change impact", "Use change planning, references, dependencies, and applicable coding intelligence before modifying files.", ["inspect"]));
    steps.push(step("plan-change", "Create a bounded change plan", "Define the intended edits, affected files, constraints, and verification requirements before writing.", ["impact"]));
    steps.push(step("edit", "Apply safe changes", "Use safe edit operations with current file hashes and never bypass stale-write protection.", ["plan-change"]));
  }

  if (actions.includes("review") || taskType === "review") {
    steps.push(step("review", "Review the resulting change set", "Inspect staged, unstaged, and untracked changes and compare them with the requested scope.", ["inspect"]));
  }

  if (actions.includes("test") || actions.includes("edit") || actions.includes("create") || actions.includes("delete") || taskType === "migration") {
    const dependency = steps.some(item => item.id === "edit") ? ["edit"] : ["inspect"];
    steps.push(step("verify-plan", "Plan verification", "Select verification checks supported by actual workspace state and project scripts.", dependency));
    steps.push(step("verify", "Execute verification", "Run only planner-generated verification checks and inspect their actual results.", ["verify-plan"]));
  }

  if (actions.includes("edit") || actions.includes("create") || actions.includes("delete") || taskType === "migration") {
    steps.push(step("recover", "Recover from verification failure if necessary", "If verification fails, diagnose the actual failure, make only justified follow-up edits, and verify again.", ["verify"]));
  }

  steps.push(step("report", "Report outcome", "Summarize completed work, verification evidence, unresolved blockers, and actions that were intentionally not performed.", [steps.at(-1)?.id || "understand"]));

  const boundedSteps = steps.slice(0, MAX_STEPS);
  const dependencies = boundedSteps.map(item => ({ id: item.id, dependsOn: item.dependsOn }));

  return {
    ok: true,
    task: {
      type: taskType,
      goal: text,
      actions,
      targets: { files },
      constraints,
      ambiguity
    },
    steps: boundedSteps,
    dependencies,
    executionPolicy: {
      maxSteps: MAX_STEPS,
      noArbitraryCommands: true,
      noCommitOrPushUnlessExplicitlyApproved: true,
      safeEditRequiredForExistingFiles: true,
      verificationRequiredAfterChanges: true
    },
    context: { recentMessages: Array.isArray(conversation) ? conversation.slice(-6).length : 0 },
    limitations: [
      "Task decomposition is a bounded execution outline, not hidden chain-of-thought or a guarantee of task success.",
      "The Agent may replan after tool results, errors, newly discovered dependencies, or verification failures.",
      "Ambiguous tasks should be clarified or narrowed before consequential changes when evidence is insufficient."
    ]
  };
}
