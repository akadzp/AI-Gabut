const MAX_EVENTS = 32;
const TERMINAL_STATES = new Set(['completed', 'blocked', 'failed', 'stopped']);

function clean(value, max = 2000) {
  return String(value ?? '').trim().slice(0, max);
}

function unique(values) {
  return [...new Set((Array.isArray(values) ? values : []).map(v => clean(v, 200)).filter(Boolean))];
}

function normalizePlan(plan) {
  const phases = Array.isArray(plan?.phases) ? plan.phases : [];
  return phases.map((phase, index) => ({
    id: clean(phase?.id || `phase-${index + 1}`, 100),
    title: clean(phase?.title || `Phase ${index + 1}`, 200),
    purpose: clean(phase?.purpose, 1000),
    dependsOn: unique(phase?.dependsOn),
    gate: clean(phase?.gate, 120) || null
  }));
}

function phaseMap(phases) {
  return new Map(phases.map(phase => [phase.id, phase]));
}

function validateDependencies(phases) {
  const ids = new Set(phases.map(p => p.id));
  const errors = [];
  for (const phase of phases) {
    for (const dependency of phase.dependsOn) {
      if (!ids.has(dependency)) errors.push(`${phase.id} depends on unknown phase ${dependency}`);
      if (dependency === phase.id) errors.push(`${phase.id} cannot depend on itself`);
    }
  }
  return errors;
}

function nextRunnable(phases, state) {
  const completed = new Set(state.completedPhases || []);
  return phases.find(phase => !completed.has(phase.id) && phase.dependsOn.every(dep => completed.has(dep))) || null;
}

export function createExecutionState({ plan, sessionId = null } = {}) {
  const phases = normalizePlan(plan);
  const dependencyErrors = validateDependencies(phases);
  const state = {
    ok: dependencyErrors.length === 0,
    status: dependencyErrors.length ? 'blocked' : 'ready',
    sessionId: clean(sessionId, 120) || null,
    currentPhase: null,
    completedPhases: [],
    failedPhases: [],
    blockedPhases: [],
    events: [],
    stepCount: 0,
    dependencyErrors,
    policy: {
      bounded: true,
      maxEvents: MAX_EVENTS,
      noImplicitCommitOrPush: true,
      requiresGateEvidence: true,
      replanOnMaterialStateChange: true
    }
  };

  if (state.ok) {
    const first = nextRunnable(phases, state);
    state.currentPhase = first?.id || null;
    state.status = first ? 'ready' : 'completed';
  }
  return state;
}

export function advanceExecution({ plan, state, phaseId, outcome = 'success', evidence = [], note = '' } = {}) {
  const phases = normalizePlan(plan);
  const map = phaseMap(phases);
  const current = state || createExecutionState({ plan });
  const targetId = clean(phaseId || current.currentPhase, 100);
  const target = map.get(targetId);

  if (!target) return { ok: false, error: `Unknown phase: ${targetId}`, state: current };
  if (TERMINAL_STATES.has(current.status)) return { ok: false, error: `Execution is already ${current.status}`, state: current };
  if (current.currentPhase !== target.id) return { ok: false, error: `Phase ${target.id} is not the current phase`, state: current };

  const normalizedOutcome = clean(outcome, 40).toLowerCase();
  const allowed = new Set(['success', 'failure', 'blocked', 'skipped']);
  if (!allowed.has(normalizedOutcome)) return { ok: false, error: `Unsupported outcome: ${normalizedOutcome}`, state: current };

  const next = structuredClone(current);
  next.stepCount += 1;
  next.events.push({ phaseId: target.id, outcome: normalizedOutcome, evidence: unique(evidence).slice(0, 12), note: clean(note, 1000) });
  next.events = next.events.slice(-MAX_EVENTS);

  if (normalizedOutcome === 'success' || normalizedOutcome === 'skipped') {
    if (!next.completedPhases.includes(target.id)) next.completedPhases.push(target.id);
    next.failedPhases = next.failedPhases.filter(id => id !== target.id);
    next.blockedPhases = next.blockedPhases.filter(id => id !== target.id);
  } else if (normalizedOutcome === 'failure') {
    if (!next.failedPhases.includes(target.id)) next.failedPhases.push(target.id);
    next.status = 'failed';
    next.currentPhase = target.id;
    return { ok: true, state: next, transition: 'recovery-required', replanRequired: true };
  } else {
    if (!next.blockedPhases.includes(target.id)) next.blockedPhases.push(target.id);
    next.status = 'blocked';
    next.currentPhase = target.id;
    return { ok: true, state: next, transition: 'blocked', replanRequired: true };
  }

  const following = nextRunnable(phases, next);
  if (!following) {
    next.currentPhase = null;
    next.status = next.completedPhases.length === phases.length ? 'completed' : 'blocked';
  } else {
    next.currentPhase = following.id;
    next.status = 'ready';
  }

  return { ok: true, state: next, transition: following ? 'advance' : next.status, replanRequired: false };
}

export function requestExecutionReplan({ state, reason, materialChange = true } = {}) {
  const current = state || {};
  return {
    ok: true,
    replanRequired: Boolean(materialChange),
    status: materialChange ? 'replan-required' : current.status || 'ready',
    reason: clean(reason, 1000),
    currentPhase: current.currentPhase || null,
    completedPhases: unique(current.completedPhases),
    policy: 'Create a fresh execution plan from current workspace/tool evidence before continuing consequential actions.'
  };
}
