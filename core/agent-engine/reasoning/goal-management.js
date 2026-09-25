const MAX_GOALS = 12;
const MAX_CRITERIA = 16;
const MAX_CONSTRAINTS = 16;
const MAX_EVENTS = 24;

function clean(value, max = 600) {
  return String(value ?? '').trim().slice(0, max);
}

function unique(values, max = MAX_CRITERIA) {
  return [...new Set((Array.isArray(values) ? values : [])
    .map(value => clean(value, 500))
    .filter(Boolean))].slice(0, max);
}

function normalizeCriteria(criteria) {
  return (Array.isArray(criteria) ? criteria : []).slice(0, MAX_CRITERIA).map((item, index) => ({
    id: clean(item?.id || `criterion-${index + 1}`, 100),
    description: clean(item?.description || item?.text || '', 500),
    required: item?.required !== false,
    status: ['pending', 'met', 'failed', 'unknown'].includes(item?.status) ? item.status : 'pending',
    evidence: unique(item?.evidence, 6)
  })).filter(item => item.description);
}

function normalizeGoals(goals) {
  return (Array.isArray(goals) ? goals : []).slice(0, MAX_GOALS).map((goal, index) => ({
    id: clean(goal?.id || `goal-${index + 1}`, 100),
    title: clean(goal?.title || `Goal ${index + 1}`, 220),
    description: clean(goal?.description || goal?.goal || '', 800),
    priority: ['critical', 'high', 'normal', 'low'].includes(goal?.priority) ? goal.priority : 'normal',
    dependsOn: unique(goal?.dependsOn, MAX_GOALS),
    criteria: normalizeCriteria(goal?.criteria)
  }));
}

function validateGoalGraph(goals) {
  const ids = new Set(goals.map(goal => goal.id));
  const errors = [];
  for (const goal of goals) {
    for (const dependency of goal.dependsOn) {
      if (!ids.has(dependency)) errors.push(`${goal.id} depends on unknown goal ${dependency}`);
      if (dependency === goal.id) errors.push(`${goal.id} cannot depend on itself`);
    }
  }
  return errors;
}

function inferStatus(criteria) {
  const required = criteria.filter(item => item.required);
  if (!required.length) return 'active';
  if (required.some(item => item.status === 'failed')) return 'blocked';
  if (required.every(item => item.status === 'met')) return 'completed';
  return 'active';
}

export function createGoalState({ prompt = '', understanding = null, goals = [], criteria = [], constraints = [] } = {}) {
  const rootDescription = clean(prompt || understanding?.goal, 1200);
  const rootCriteria = normalizeCriteria(criteria.length ? criteria : [
    { id: 'task-outcome', description: 'The requested outcome is achieved and supported by observable evidence.' }
  ]);
  const normalizedGoals = normalizeGoals(goals.length ? goals : [{
    id: 'primary',
    title: 'Complete requested task',
    description: rootDescription || 'Complete the current user request.',
    priority: 'critical',
    criteria: rootCriteria
  }]);
  const graphErrors = validateGoalGraph(normalizedGoals);

  return {
    ok: graphErrors.length === 0,
    status: graphErrors.length ? 'blocked' : 'active',
    primaryGoalId: normalizedGoals[0]?.id || null,
    goals: normalizedGoals,
    constraints: unique(constraints, MAX_CONSTRAINTS),
    events: [],
    graphErrors,
    policy: {
      bounded: true,
      maxGoals: MAX_GOALS,
      maxCriteria: MAX_CRITERIA,
      noImplicitScopeExpansion: true,
      completionRequiresEvidence: true,
      failedCriteriaBlockCompletion: true,
      noImplicitCommitOrPush: true
    }
  };
}

export function updateGoalState({ state, goalId, criterionId, status = 'pending', evidence = [], note = '' } = {}) {
  const current = state || { goals: [], events: [], status: 'active' };
  const next = structuredClone(current);
  const goal = next.goals.find(item => item.id === clean(goalId, 100));
  if (!goal) return { ok: false, error: `Unknown goal: ${clean(goalId, 100)}`, state: current };
  const criterion = goal.criteria.find(item => item.id === clean(criterionId, 100));
  if (!criterion) return { ok: false, error: `Unknown criterion: ${clean(criterionId, 100)}`, state: current };
  if (!['pending', 'met', 'failed', 'unknown'].includes(status)) return { ok: false, error: `Unsupported criterion status: ${status}`, state: current };

  criterion.status = status;
  criterion.evidence = unique([...(criterion.evidence || []), ...evidence], 6);
  next.events.push({ goalId: goal.id, criterionId: criterion.id, status, evidence: unique(evidence, 6), note: clean(note, 800) });
  next.events = next.events.slice(-MAX_EVENTS);

  for (const item of next.goals) item.status = inferStatus(item.criteria);
  const requiredGoals = next.goals.filter(item => item.priority === 'critical' || item.id === next.primaryGoalId);
  next.status = requiredGoals.every(item => item.status === 'completed') ? 'completed' : requiredGoals.some(item => item.status === 'blocked') ? 'blocked' : 'active';
  return { ok: true, state: next, transition: next.status === 'completed' ? 'goal-completed' : status === 'failed' ? 'goal-blocked' : 'goal-progressed' };
}

export function assessGoals({ state } = {}) {
  const current = state || { goals: [], constraints: [], events: [] };
  const goals = (current.goals || []).map(goal => ({
    id: goal.id,
    title: goal.title,
    status: goal.status || inferStatus(goal.criteria || []),
    requiredCriteria: (goal.criteria || []).filter(item => item.required).map(item => ({ id: item.id, status: item.status, evidence: item.evidence || [] })),
    unmetCriteria: (goal.criteria || []).filter(item => item.required && item.status !== 'met').map(item => item.id)
  }));
  const blockers = goals.filter(goal => goal.status === 'blocked').map(goal => goal.id);
  return {
    ok: true,
    status: current.status || 'active',
    goals,
    blockers,
    constraints: unique(current.constraints, MAX_CONSTRAINTS),
    completion: {
      complete: (current.status || 'active') === 'completed',
      evidenceRequired: true,
      unresolvedGoals: goals.filter(goal => goal.status !== 'completed').map(goal => goal.id)
    },
    policy: current.policy || { completionRequiresEvidence: true, noImplicitScopeExpansion: true }
  };
}
