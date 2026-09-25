const MAX_REASONS = 12;
const MAX_CHANGES = 16;
const MAX_PHASES = 16;

function clean(value, max = 500) {
  return String(value ?? '').trim().slice(0, max);
}

function unique(values, max = MAX_REASONS) {
  return [...new Set((Array.isArray(values) ? values : [])
    .map(value => clean(value, 300))
    .filter(Boolean))].slice(0, max);
}

function normalizePhase(phase, index) {
  return {
    id: clean(phase?.id || `phase-${index + 1}`, 100),
    title: clean(phase?.title || `Phase ${index + 1}`, 200),
    purpose: clean(phase?.purpose, 600),
    dependsOn: unique(phase?.dependsOn, MAX_PHASES),
    gate: clean(phase?.gate, 160) || null
  };
}

function normalizePlan(plan) {
  const phases = Array.isArray(plan?.phases) ? plan.phases : [];
  return phases.slice(0, MAX_PHASES).map(normalizePhase);
}

function changedFilesFromEvidence(evidence) {
  const values = [
    ...(Array.isArray(evidence?.changedFiles) ? evidence.changedFiles : []),
    ...(Array.isArray(evidence?.affectedFiles) ? evidence.affectedFiles : []),
    ...(Array.isArray(evidence?.newFiles) ? evidence.newFiles : []),
    ...(Array.isArray(evidence?.deletedFiles) ? evidence.deletedFiles : [])
  ];
  return unique(values, MAX_CHANGES);
}

function phaseIdSet(phases) {
  return new Set(phases.map(phase => phase.id));
}

function completedSet(state) {
  return new Set(Array.isArray(state?.completedPhases) ? state.completedPhases : []);
}

function normalizeReason(reason) {
  const text = clean(reason, 500).toLowerCase();
  if (!text) return 'material-state-change';
  if (/verification|test|check|assert|fail/.test(text)) return 'verification-failure';
  if (/stale|changed|modified|workspace|file/.test(text)) return 'workspace-state-change';
  if (/dependency|impact|reference|contract|schema/.test(text)) return 'new-impact-evidence';
  if (/constraint|scope|requirement|user/.test(text)) return 'constraint-change';
  if (/tool|command|permission/.test(text)) return 'execution-blocker';
  return 'material-state-change';
}

export function createReplan({ plan, state, reason, evidence = {}, constraints = [] } = {}) {
  const phases = normalizePlan(plan);
  const ids = phaseIdSet(phases);
  const completed = completedSet(state);
  const reasonCode = normalizeReason(reason);
  const changedFiles = changedFilesFromEvidence(evidence);
  const unknownCompleted = [...completed].filter(id => !ids.has(id));
  const currentPhase = clean(state?.currentPhase, 100) || null;

  const remainingPhases = phases.filter(phase => !completed.has(phase.id));
  const invalidState = unknownCompleted.length > 0 || (currentPhase && !ids.has(currentPhase));

  const mustReinspect = new Set(['verification-failure', 'workspace-state-change', 'new-impact-evidence', 'constraint-change', 'execution-blocker']);
  const inspectFirst = mustReinspect.has(reasonCode) ? [
    'Refresh current workspace and tool evidence before selecting consequential actions.',
    ...(changedFiles.length ? [`Re-read evidence for changed files: ${changedFiles.slice(0, 8).join(', ')}`] : []),
    ...(reasonCode === 'verification-failure' ? ['Diagnose the actual verification failure before proposing another edit.'] : []),
    ...(reasonCode === 'new-impact-evidence' ? ['Re-check affected references, dependencies, contracts, or schemas.'] : [])
  ] : ['Confirm that the existing evidence is still current.'];

  const requiredActions = [
    'Do not assume unfinished phases remain valid after a material state change.',
    ...inspectFirst,
    'Recompute phase dependencies and verification gates from current evidence.',
    'Preserve completed work only when its evidence remains valid.'
  ];

  const preservedPhases = phases.filter(phase => completed.has(phase.id)).map(phase => phase.id);
  const invalidatedPhases = reasonCode === 'constraint-change' || reasonCode === 'new-impact-evidence'
    ? remainingPhases.map(phase => phase.id)
    : [];

  const warnings = [];
  if (invalidState) warnings.push('Current execution state references a phase outside the supplied plan; rebuild state from fresh plan evidence.');
  if (!phases.length) warnings.push('No prior phases were supplied; create a fresh plan from task understanding and current evidence.');
  if (!changedFiles.length && ['workspace-state-change', 'new-impact-evidence', 'verification-failure'].includes(reasonCode)) {
    warnings.push('No changed-file evidence was supplied; do not infer affected files without fresh inspection.');
  }

  return {
    ok: true,
    type: 'replan',
    reason: { code: reasonCode, description: clean(reason, 500) || 'Material execution state changed.' },
    sourceState: {
      status: clean(state?.status, 80) || null,
      currentPhase,
      completedPhases: preservedPhases,
      stepCount: Number.isFinite(state?.stepCount) ? state.stepCount : 0
    },
    evidence: {
      changedFiles,
      constraints: unique(constraints, MAX_REASONS),
      evidenceKeys: Object.keys(evidence || {}).slice(0, 20)
    },
    replan: {
      required: true,
      inspectFirst: unique(inspectFirst),
      preserveCompletedWhenEvidenceValid: true,
      invalidatedPhases,
      remainingPhaseIds: remainingPhases.map(phase => phase.id),
      requiredActions: unique(requiredActions)
    },
    warnings,
    policy: {
      bounded: true,
      noImplicitEdit: true,
      noImplicitCommitOrPush: true,
      freshEvidenceRequired: true,
      completedWorkRequiresEvidence: true
    }
  };
}
