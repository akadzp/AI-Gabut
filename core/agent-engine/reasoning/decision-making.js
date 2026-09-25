const MAX_EVIDENCE = 12;

function clean(value, max = 500) {
  return String(value ?? '').trim().slice(0, max);
}

function unique(values) {
  return [...new Set((Array.isArray(values) ? values : []).map(v => clean(v, 300)).filter(Boolean))].slice(0, MAX_EVIDENCE);
}

export function decideNextAction({ context = {}, executionState = {}, latestResult = null } = {}) {
  const ambiguity = Array.isArray(context?.ambiguity?.unresolved) ? context.ambiguity.unresolved : [];
  const ready = context?.decision?.readyForPlanning !== false;
  const status = clean(executionState?.status, 60) || 'ready';
  const latestOk = latestResult?.ok !== false;
  const verificationFailed = latestResult?.type === 'verification' && latestResult?.summary?.failed > 0;
  const evidence = unique([
    ...(Array.isArray(latestResult?.evidence) ? latestResult.evidence : []),
    ...(Array.isArray(latestResult?.observations) ? latestResult.observations : [])
  ]);

  if (!ready || ambiguity.length) {
    return { ok: true, decision: 'clarify', reason: 'Task context is not ready for consequential execution.', requiredEvidence: unique(ambiguity), confidence: 'high' };
  }
  if (status === 'replan-required' || status === 'failed' || status === 'blocked') {
    return { ok: true, decision: 'replan', reason: 'Execution state requires a fresh plan before continuing.', requiredEvidence: evidence, confidence: 'high' };
  }
  if (verificationFailed) {
    return { ok: true, decision: 'diagnose', reason: 'Verification failed; diagnose actual failure before another edit.', requiredEvidence: evidence, confidence: 'high' };
  }
  if (!latestResult) {
    return { ok: true, decision: 'inspect', reason: 'No execution evidence is available yet.', requiredEvidence: [], confidence: 'medium' };
  }
  if (!latestOk) {
    return { ok: true, decision: 'recover', reason: 'The latest action failed; inspect the actual error before changing state.', requiredEvidence: evidence, confidence: 'high' };
  }
  if (status === 'completed') {
    return { ok: true, decision: 'report', reason: 'Execution reached a terminal completed state.', requiredEvidence: evidence, confidence: 'high' };
  }
  return { ok: true, decision: 'continue', reason: 'Current evidence supports continuing the bounded execution plan.', requiredEvidence: evidence, confidence: 'medium' };
}
