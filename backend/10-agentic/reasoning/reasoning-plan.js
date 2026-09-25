const MAX_TEXT = 12000;
const MAX_STEPS = 16;
const MAX_PHASES = 12;
const MAX_HORIZON = 4;

const unique = (values = []) => [...new Set((Array.isArray(values) ? values : []).map(v => String(v ?? '').trim()).filter(Boolean))];

function normalizeSteps(steps = []) {
  return steps.slice(0, MAX_STEPS).map((item, index) => ({
    id: String(item?.id || `step-${index + 1}`),
    title: String(item?.title || `Step ${index + 1}`).trim(),
    purpose: String(item?.purpose || '').trim(),
    dependsOn: unique(item?.dependsOn).slice(0, 8)
  }));
}

function phase(id, title, purpose, stepIds, dependsOn = [], gate = null) {
  return { id, title, purpose, stepIds, dependsOn, gate };
}

function inferLongHorizon({ taskType, actions, stepCount, targetCount }) {
  if (taskType === 'explanation') return false;
  return stepCount > 5 || targetCount > 3 || actions.some(action => ['migrate', 'refactor', 'edit', 'create', 'delete'].includes(action));
}

function buildPhases({ steps, longHorizon, needsChange, needsVerification }) {
  const ids = steps.map(step => step.id);
  const phases = [];
  const pick = (...wanted) => ids.filter(id => wanted.includes(id));

  phases.push(phase('scope', 'Establish scope', 'Confirm the task/goal context and keep the execution boundary fixed.', pick('understand', 'resolve-ambiguity'), [], 'scope-confirmed'));
  phases.push(phase('evidence', 'Gather evidence', 'Collect only evidence needed for the current planning horizon.', pick('inspect'), ['scope'], 'sufficient-evidence'));

  if (needsChange) {
    phases.push(phase('impact', 'Assess impact', 'Use project intelligence before committing to a broad change.', pick('impact', 'plan-change'), ['evidence'], 'impact-understood'));
    phases.push(phase('change', 'Execute bounded changes', 'Apply only changes justified by the current plan and evidence.', pick('edit'), ['impact'], 'safe-edit-complete'));
  }

  if (needsVerification) {
    phases.push(phase('verify', 'Verify outcome', 'Use generated verification checks and actual results as the completion evidence.', pick('verify-plan', 'verify'), [needsChange ? 'change' : 'evidence'], 'verification-passed'));
  }

  phases.push(phase('report', 'Close the task', 'Report actual outcome, evidence, blockers, and any remaining work.', pick('report'), [phases.at(-1)?.id || 'evidence'], 'outcome-reported'));

  if (longHorizon) {
    return phases.slice(0, MAX_PHASES).map((item, index) => ({
      ...item,
      horizon: Math.min(Math.floor(index / 2) + 1, MAX_HORIZON)
    }));
  }
  return phases.slice(0, MAX_PHASES);
}

function buildReplanTriggers({ longHorizon, needsChange }) {
  const triggers = [
    'material user constraint change',
    'new dependency or affected file discovered',
    'tool result invalidates a planned assumption',
    'verification failure',
    'stale file detected'
  ];
  if (longHorizon) triggers.push('current horizon completes with unresolved downstream dependency');
  if (needsChange) triggers.push('safe edit cannot be applied without expanding scope');
  return triggers;
}

export function buildReasoningPlan({
  prompt = '',
  context = null,
  understanding = null,
  decomposition = null,
  planning = null,
  goals = null,
  evidence = null
} = {}) {
  const goal = String(prompt || context?.task?.goal || understanding?.goal || '').trim().slice(0, MAX_TEXT);
  const taskType = context?.task?.type || understanding?.taskType || decomposition?.task?.type || planning?.plan?.taskType || 'general';
  const actions = unique(context?.task?.actions || understanding?.actions || decomposition?.task?.actions || planning?.plan?.actions);
  const constraints = unique(context?.constraints || understanding?.constraints || decomposition?.task?.constraints || planning?.plan?.constraints);
  const targets = unique(context?.task?.targets?.files || understanding?.targets?.files || decomposition?.task?.targets?.files || planning?.plan?.targets?.files);
  const ambiguity = unique(context?.ambiguity?.unresolved || understanding?.ambiguity || decomposition?.task?.ambiguity || planning?.plan?.ambiguity);
  const steps = normalizeSteps(decomposition?.steps || planning?.sourceSteps || []);
  const planPhases = Array.isArray(planning?.plan?.phases) ? planning.plan.phases : [];
  const hasChange = ['edit', 'create', 'delete', 'migrate', 'refactor'].some(action => actions.includes(action)) || ['modification', 'migration', 'refactoring'].includes(taskType);
  const needsVerification = hasChange || actions.some(action => ['test', 'verify'].includes(action));
  const longHorizon = inferLongHorizon({ taskType, actions, stepCount: steps.length || planPhases.length, targetCount: targets.length });
  const phases = buildPhases({ steps: steps.length ? steps : planPhases, longHorizon, needsChange: hasChange, needsVerification });

  return {
    ok: true,
    type: 'integrated-reasoning-plan',
    task: { type: taskType, goal, actions, targets: { files: targets }, constraints },
    readiness: {
      ready: ambiguity.length === 0 && Boolean(context?.decision?.readyForPlanning ?? true),
      unresolvedAmbiguities: ambiguity,
      requiresClarification: ambiguity.length > 0
    },
    strategy: {
      mode: longHorizon ? 'long-horizon' : 'bounded',
      horizonCount: longHorizon ? Math.min(MAX_HORIZON, Math.max(2, Math.ceil((steps.length || phases.length) / 4))) : 1,
      rollingHorizon: longHorizon,
      replanAfterEvidence: true
    },
    steps,
    phases,
    dependencies: steps.map(item => ({ id: item.id, dependsOn: item.dependsOn })),
    gates: phases.map(item => ({ phaseId: item.id, gate: item.gate })),
    goals: Array.isArray(goals?.goals) ? goals.goals.slice(0, 12) : (Array.isArray(context?.goals) ? context.goals.slice(0, 12) : []),
    replanTriggers: buildReplanTriggers({ longHorizon, needsChange: hasChange }),
    executionPolicy: {
      bounded: true,
      maxSteps: MAX_STEPS,
      maxPhases: MAX_PHASES,
      maxHorizons: MAX_HORIZON,
      noArbitraryCommands: true,
      safeEditRequiredForExistingFiles: hasChange,
      verificationRequiredAfterChanges: needsVerification,
      noImplicitCommitOrPush: true,
      preserveConstraints: true,
      noScopeExpansionWithoutEvidence: true
    },
    evidence: {
      hasIntegratedContext: Boolean(context),
      hasUnderstanding: Boolean(understanding),
      decompositionSteps: steps.length,
      planningPhases: planPhases.length,
      targetFiles: targets.length,
      constraints: constraints.length,
      suppliedEvidenceKeys: Object.keys(evidence || {}).slice(0, 20)
    },
    limitations: [
      'This is an operational planning artifact, not hidden chain-of-thought.',
      'Long-horizon plans use bounded rolling horizons and must be refreshed when material evidence changes.',
      'A planned phase is not evidence that the phase succeeded.'
    ]
  };
}
