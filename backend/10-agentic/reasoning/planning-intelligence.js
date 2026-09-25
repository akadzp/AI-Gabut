const MAX_TEXT = 12000;
const MAX_PHASES = 12;

function unique(values) {
  return [...new Set((Array.isArray(values) ? values : []).map(value => String(value || '').trim()).filter(Boolean))];
}

function normalizeSteps(steps = []) {
  return steps.slice(0, MAX_PHASES).map((item, index) => ({
    id: String(item?.id || `step-${index + 1}`),
    title: String(item?.title || `Step ${index + 1}`).trim(),
    purpose: String(item?.purpose || '').trim(),
    dependsOn: unique(item?.dependsOn || [])
  }));
}

function phase(id, title, purpose, dependsOn = [], gate = null) {
  return { id, title, purpose, dependsOn, gate };
}

export function createExecutionPlan({ prompt = '', understanding = null, decomposition = null, evidence = null } = {}) {
  const goal = String(prompt || understanding?.goal || '').trim().slice(0, MAX_TEXT);
  const taskType = understanding?.taskType || decomposition?.task?.type || 'general';
  const actions = unique(understanding?.actions || decomposition?.task?.actions || []);
  const constraints = unique(understanding?.constraints || decomposition?.task?.constraints || []);
  const ambiguity = unique(understanding?.ambiguity || decomposition?.task?.ambiguity || []);
  const targets = unique(understanding?.targets?.files || decomposition?.task?.targets?.files || []);
  const sourceSteps = normalizeSteps(decomposition?.steps || []);
  const phases = [];

  phases.push(phase('scope', 'Confirm scope and constraints', 'Use the structured task evidence as the execution boundary.', [], 'task-scope-confirmed'));

  if (ambiguity.length) {
    phases.push(phase('clarify', 'Resolve material ambiguity', 'Do not perform consequential actions until missing scope or constraints are resolved.', ['scope'], 'ambiguity-resolved'));
  }

  const inspectDependency = ambiguity.length ? ['clarify'] : ['scope'];
  phases.push(phase('evidence', 'Gather targeted evidence', 'Inspect only the workspace evidence required by the task and avoid broad unrelated reads.', inspectDependency, 'sufficient-evidence'));

  const needsChange = ['edit', 'create', 'delete', 'migrate'].some(action => actions.includes(action)) || ['modification', 'migration', 'refactoring'].includes(taskType);
  if (needsChange) {
    phases.push(phase('impact', 'Assess impact and affected scope', 'Use references, dependencies, contracts, schemas, framework evidence, or migration analysis when applicable.', ['evidence'], 'impact-understood'));
    phases.push(phase('change', 'Apply bounded changes', 'Make the smallest justified safe edits within the approved scope and current file versions.', ['impact'], 'safe-edit-complete'));
    phases.push(phase('verify', 'Verify the resulting state', 'Generate and execute relevant verification checks from actual workspace state.', ['change'], 'verification-passed'));
  } else if (actions.includes('test') || actions.includes('verify')) {
    phases.push(phase('verify', 'Verify the requested state', 'Generate and execute relevant checks without inventing commands.', ['evidence'], 'verification-passed'));
  }

  if (actions.includes('review') || taskType === 'review') {
    phases.push(phase('review', 'Review the resulting change set', 'Compare actual staged, unstaged, and untracked changes with the requested scope.', [phases.at(-1)?.id || 'evidence'], 'review-complete'));
  }

  phases.push(phase('report', 'Report outcome and blockers', 'Summarize completed work, actual verification evidence, unresolved blockers, and intentionally skipped actions.', [phases.at(-1)?.id || 'evidence'], 'outcome-reported'));

  const bounded = phases.slice(0, MAX_PHASES);
  const evidenceSummary = {
    hasUnderstanding: Boolean(understanding),
    decompositionSteps: sourceSteps.length,
    targetFiles: targets.length,
    constraints: constraints.length,
    ambiguity: ambiguity.length,
    providedEvidenceKeys: Object.keys(evidence || {}).slice(0, 20)
  };

  return {
    ok: true,
    plan: {
      goal,
      taskType,
      actions,
      targets: { files: targets },
      constraints,
      phases: bounded,
      dependencies: bounded.map(item => ({ id: item.id, dependsOn: item.dependsOn })),
      executionPolicy: {
        maxPhases: MAX_PHASES,
        bounded: true,
        safeEditRequiredForExistingFiles: needsChange,
        verificationRequiredAfterChanges: needsChange,
        noArbitraryCommands: true,
        noCommitOrPushUnlessExplicitlyApproved: true,
        replanTriggers: ['new dependency discovered', 'tool error changes scope', 'verification failure', 'stale file detected', 'material user constraint change']
      }
    },
    evidence: evidenceSummary,
    sourceDecomposition: sourceSteps.map(item => item.id),
    limitations: [
      'Execution planning is a bounded operational plan, not hidden chain-of-thought.',
      'The plan may be revised when actual tool results materially change the task state.',
      'A planned phase is not evidence that the underlying action succeeded.'
    ]
  };
}
