const MAX_TOOL_HISTORY = 40;
const MAX_OBSERVATIONS = 30;

export function createAgentContext({ prompt, provider, model, conversation = [], memories = [] }) {
  return {
    goal: prompt,
    provider,
    model,
    conversation,
    memories,
    retrievedMemories: [],
    plan: [],
    currentStep: 0,
    observations: [],
    toolHistory: [],
    status: "planning"
  };
}

export function recordObservation(context, observation) {
  context.observations.push(observation);
  if (context.observations.length > MAX_OBSERVATIONS) context.observations.shift();
}

export function recordToolResult(context, entry) {
  context.toolHistory.push(entry);
  if (context.toolHistory.length > MAX_TOOL_HISTORY) context.toolHistory.shift();
}

export function setPlan(context, plan) {
  context.plan = Array.isArray(plan) ? plan : [];
  context.currentStep = 0;
  context.status = context.plan.length ? "executing" : "done";
}

export function advancePlan(context) {
  context.currentStep += 1;
  if (context.currentStep >= context.plan.length) context.status = "done";
}

export function getCurrentStep(context) {
  return context.plan[context.currentStep] ?? null;
}
