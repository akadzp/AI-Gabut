const MAX_CONSTRAINTS = 20;
const MAX_AMBIGUITIES = 12;
const MAX_GOALS = 12;

function clean(value, max = 800) {
  return String(value ?? '').trim().slice(0, max);
}

function unique(values, max) {
  return [...new Set((Array.isArray(values) ? values : []).map(v => clean(v, 500)).filter(Boolean))].slice(0, max);
}

function inferConstraintDetails(understanding, prompt) {
  const constraints = Array.isArray(understanding?.constraints) ? understanding.constraints : [];
  const text = String(prompt || '').trim();
  const details = constraints.map(code => ({
    code,
    source: 'task-understanding',
    enforcedBy: code === 'no-commit-or-push' ? 'approval-boundary' : code === 'read-only' || code === 'no-change' ? 'no-mutation' : code === 'preserve-api' ? 'contract-preservation' : code === 'scope-limited' ? 'target-scope' : 'agent-policy'
  }));
  if (/\b(jangan|do not|don't)\b[^.\n]*(?:commit|push)/i.test(text) && !constraints.includes('no-commit-or-push')) {
    details.push({ code: 'no-commit-or-push', source: 'task-text', enforcedBy: 'approval-boundary' });
  }
  return details.slice(0, MAX_CONSTRAINTS);
}

function resolveAmbiguitySignals(understanding, conversation = []) {
  const signals = unique(understanding?.ambiguity, MAX_AMBIGUITIES);
  const recent = Array.isArray(conversation) ? conversation.slice(-6) : [];
  const hasContext = recent.some(item => String(item?.content || '').trim().length > 0);
  const resolved = [];
  const unresolved = [];
  for (const signal of signals) {
    if (signal === 'referent-may-depend-on-context' && hasContext) resolved.push({ signal, resolution: 'Use recent conversation context as supporting evidence; confirm target before mutation.' });
    else unresolved.push({ signal, requiredAction: 'Clarify or inspect before consequential action.' });
  }
  return { resolved, unresolved, requiresClarification: unresolved.length > 0 };
}

function normalizeGoals(understanding, goalState) {
  const goals = Array.isArray(goalState?.goals) ? goalState.goals : [];
  if (goals.length) return goals;
  return [{
    id: 'primary',
    title: 'Complete requested task',
    description: clean(understanding?.goal || '', 1200),
    priority: 'critical',
    criteria: [{ id: 'task-outcome', description: 'Requested outcome is achieved and supported by observable evidence.', required: true, status: 'pending', evidence: [] }]
  }];
}

export function establishTaskGoalContext({ prompt = '', conversation = [], understanding = null, goalState = null, goals = [], criteria = [], constraints = [] } = {}) {
  const task = understanding || {
    ok: true,
    taskType: 'general',
    goal: clean(prompt, 1200),
    actions: [],
    targets: { files: [] },
    constraints: [],
    ambiguity: [],
    confidence: 'low'
  };
  const inferredConstraintDetails = inferConstraintDetails(task, prompt);
  const mergedConstraints = unique([
    ...inferredConstraintDetails.map(item => item.code),
    ...constraints
  ], MAX_CONSTRAINTS);
  const ambiguity = resolveAmbiguitySignals(task, conversation);
  const effectiveGoals = normalizeGoals(task, goalState);

  return {
    ok: true,
    type: 'task-goal-context',
    task: {
      type: task.taskType || 'general',
      goal: clean(task.goal || prompt, 1200),
      actions: unique(task.actions, 16),
      targets: task.targets || { files: [] },
      confidence: task.confidence || 'low'
    },
    goals: effectiveGoals.slice(0, MAX_GOALS),
    constraints: mergedConstraints,
    constraintDetails: inferredConstraintDetails,
    ambiguity,
    decision: {
      readyForPlanning: !ambiguity.requiresClarification,
      clarificationRequired: ambiguity.requiresClarification,
      mutationAllowed: !mergedConstraints.includes('read-only') && !mergedConstraints.includes('no-change'),
      commitOrPushAllowed: false
    },
    evidence: {
      conversationMessages: Array.isArray(conversation) ? conversation.slice(-6).length : 0,
      taskUnderstanding: Boolean(understanding),
      suppliedGoalState: Boolean(goalState)
    },
    policy: {
      bounded: true,
      noImplicitScopeExpansion: true,
      constraintsMustBePreserved: true,
      ambiguityMustBeResolvedBeforeConsequentialAction: true,
      completionRequiresObservableEvidence: true,
      noImplicitCommitOrPush: true
    }
  };
}
