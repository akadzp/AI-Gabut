const MAX_SPECIALISTS = 6;
const MAX_STAGES = 10;
const MAX_HANDOFF_ITEMS = 12;

const SPECIALISTS = [
  {
    id: 'planner', name: 'Planner Agent', capability: 'planning',
    description: 'Turns a user task into bounded stages, dependencies, gates, and acceptance criteria.',
    tools: ['understand_task', 'decompose_task', 'create_execution_plan', 'reasoning_lifecycle']
  },
  {
    id: 'coding', name: 'Coding Agent', capability: 'implementation',
    description: 'Inspects source, designs targeted edits, and applies safe code changes.',
    tools: ['search_files', 'find_symbol', 'find_references', 'analyze_impact', 'plan_change', 'edit_file']
  },
  {
    id: 'research', name: 'Research Agent', capability: 'evidence',
    description: 'Collects local project evidence and resolves unknowns before consequential actions.',
    tools: ['inspect_project', 'search_code', 'read_file', 'analyze_frameworks', 'analyze_contracts']
  },
  {
    id: 'testing', name: 'Testing Agent', capability: 'verification',
    description: 'Selects and executes bounded verification checks and interprets failures.',
    tools: ['analyze_tests', 'plan_verification', 'execute_verification', 'diagnose_verification_failure']
  },
  {
    id: 'reviewer', name: 'Reviewer Agent', capability: 'review',
    description: 'Reviews the resulting change set for correctness, scope, contracts, and safety.',
    tools: ['git_changes', 'review_change_set', 'analyze_impact', 'analyze_contracts', 'analyze_schemas']
  },
  {
    id: 'coordinator', name: 'Coordinator Agent', capability: 'orchestration',
    description: 'Coordinates specialist handoffs, preserves constraints, and decides when to replan.',
    tools: ['execution_reasoning', 'execution_control', 'replan_execution', 'goal_management']
  }
];

function clean(value, max = 1000) { return String(value ?? '').trim().slice(0, max); }
function unique(values, max = MAX_HANDOFF_ITEMS) { return [...new Set((Array.isArray(values) ? values : []).map(v => clean(v, 500)).filter(Boolean))].slice(0, max); }
function has(text, pattern) { return pattern.test(String(text || '')); }

export function getSpecialists() {
  return SPECIALISTS.map(item => ({ ...item, tools: [...item.tools] }));
}

function chooseSpecialists({ prompt, taskType = '', actions = [], targets = [] } = {}) {
  const text = `${prompt} ${taskType} ${actions.join(' ')} ${targets.join(' ')}`.toLowerCase();
  const selected = new Set(['coordinator']);

  if (has(text, /plan|rencana|architecture|arsitektur|multi.?step|refactor|migrat/)) selected.add('planner');
  if (has(text, /code|kode|implement|edit|ubah|buat|fix|bug|refactor|migrat/)) selected.add('coding');
  if (has(text, /research|cari|telusuri|inspect|pahami|evidence|dependenc|framework|api|schema/)) selected.add('research');
  if (has(text, /test|verify|verification|cek|validasi|debug|failure|gagal/)) selected.add('testing');
  if (has(text, /review|reviewer|diff|change.?set|commit|quality|audit/)) selected.add('reviewer');

  // Substantial coding tasks benefit from an explicit planner/research/verification path.
  if (selected.has('coding')) {
    selected.add('planner');
    selected.add('research');
    selected.add('testing');
  }

  const ordered = ['planner', 'research', 'coding', 'testing', 'reviewer', 'coordinator']
    .filter(id => selected.has(id));
  return ordered.slice(0, MAX_SPECIALISTS).map(id => SPECIALISTS.find(item => item.id === id));
}

function stage(id, specialistId, title, purpose, dependsOn = [], gate = 'evidence-required') {
  return { id, specialist: specialistId, title, purpose, dependsOn, gate };
}

export function buildSpecialistPlan({ prompt = '', context = null, reasoning = null, taskType = '', actions = [], targets = [] } = {}) {
  const effectiveTaskType = taskType || context?.task?.type || reasoning?.task?.type || 'general';
  const effectiveActions = actions.length ? actions : context?.task?.actions || reasoning?.task?.actions || [];
  const effectiveTargets = targets.length ? targets : context?.task?.targets?.files || reasoning?.task?.targets?.files || [];
  const specialists = chooseSpecialists({ prompt, taskType: effectiveTaskType, actions: effectiveActions, targets: effectiveTargets });
  const ids = new Set(specialists.map(item => item.id));
  const stages = [];

  if (ids.has('planner')) stages.push(stage('plan', 'planner', 'Bound the work', 'Establish scope, dependencies, constraints, and acceptance criteria.'));
  if (ids.has('research')) stages.push(stage('evidence', 'research', 'Gather project evidence', 'Inspect only the project evidence required by the current horizon.', stages.length ? [stages.at(-1).id] : []));
  if (ids.has('coding')) stages.push(stage('implement', 'coding', 'Implement bounded changes', 'Apply only safe, evidence-backed changes within the agreed scope.', stages.length ? [stages.at(-1).id] : []));
  if (ids.has('testing')) stages.push(stage('verify', 'testing', 'Verify the result', 'Run the generated verification set and classify actual failures.', stages.length ? [stages.at(-1).id] : []));
  if (ids.has('reviewer')) stages.push(stage('review', 'reviewer', 'Review the change set', 'Inspect resulting changes and observable risks before approval.', stages.length ? [stages.at(-1).id] : []));
  stages.push(stage('coordinate', 'coordinator', 'Coordinate next state', 'Record evidence, preserve constraints, and continue, recover, replan, or stop.', stages.length ? [stages.at(-1).id] : []));

  return {
    ok: true,
    type: 'specialist-orchestration-plan',
    mode: specialists.length > 1 ? 'multi-specialist' : 'single-specialist',
    task: { type: effectiveTaskType, goal: clean(prompt, 1200), actions: unique(effectiveActions, 16), targets: unique(effectiveTargets, 16) },
    specialists: specialists.map(item => ({ id: item.id, name: item.name, capability: item.capability, tools: item.tools })),
    stages: stages.slice(0, MAX_STAGES),
    coordination: {
      handoffRequired: true,
      evidenceRequiredForHandoff: true,
      preserveConstraints: true,
      replanOnMaterialEvidenceChange: true,
      noImplicitScopeExpansion: true,
      noImplicitCommitOrPush: true,
      maxActiveSpecialists: MAX_SPECIALISTS
    },
    limitations: [
      'Specialists are role boundaries over the same bounded Agent runtime; this plan does not imply hidden parallel execution.',
      'Handoffs carry observable artifacts and constraints, not hidden chain-of-thought.',
      'A specialist stage is not considered complete without evidence from its assigned tools.'
    ]
  };
}

export function createSpecialistHandoff({ plan, from, to, status = 'completed', evidence = [], constraints = [], artifacts = [] } = {}) {
  const validFrom = SPECIALISTS.some(item => item.id === from);
  const validTo = SPECIALISTS.some(item => item.id === to);
  if (!validFrom || !validTo) return { ok: false, error: 'Unknown specialist in handoff' };
  if (from === to) return { ok: false, error: 'Specialist handoff requires different specialists' };
  return {
    ok: true,
    type: 'specialist-handoff',
    from,
    to,
    status: ['completed', 'blocked', 'needs-review', 'needs-replan'].includes(status) ? status : 'completed',
    evidence: unique(evidence),
    constraints: unique(constraints),
    artifacts: unique(artifacts),
    nextAction: status === 'completed' ? 'consume-handoff-and-continue' : status,
    planType: plan?.type || null
  };
}

export function coordinateSpecialists({ plan, completedStages = [], currentStage = null, evidence = [], blockers = [] } = {}) {
  const stages = Array.isArray(plan?.stages) ? plan.stages : [];
  const completed = new Set(unique(completedStages, MAX_STAGES));
  const current = currentStage || stages.find(item => !completed.has(item.id))?.id || null;
  const stageInfo = stages.find(item => item.id === current) || null;
  const blocked = unique(blockers, MAX_HANDOFF_ITEMS);
  let decision = 'continue';
  if (blocked.length) decision = 'replan';
  else if (!current) decision = 'stop';
  else if (stageInfo?.gate === 'evidence-required' && !Array.isArray(evidence) ? true : false) decision = 'gather-evidence';

  return {
    ok: true,
    type: 'specialist-coordination-state',
    currentStage: stageInfo,
    completedStages: [...completed],
    decision,
    blockers: blocked,
    evidence: unique(evidence),
    handoff: stageInfo ? { from: completed.size ? stages.find(item => completed.has(item.id))?.specialist || null : null, to: stageInfo.specialist } : null,
    next: decision === 'continue' ? stageInfo?.specialist || null : null
  };
}

export const SPECIALIST_CAPABILITIES = [
  'planner_agent', 'coding_agent', 'research_agent', 'testing_agent', 'reviewer_agent',
  'specialist_coordination', 'agent_orchestration'
];
