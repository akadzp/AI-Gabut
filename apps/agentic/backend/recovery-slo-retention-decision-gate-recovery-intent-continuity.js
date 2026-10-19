import { createHash } from "node:crypto";
import { AgenticError } from "./errors.js";

const INTENT_KIND = "recovery-slo-retention-decision-gate-anchor-recovery-intent";
const DIGEST = /^[a-f0-9]{64}$/;
const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const clean = value => {
  if (Array.isArray(value)) return value.map(clean);
  if (!value || typeof value !== "object") return value;
  const out = {}; for (const [key, item] of Object.entries(value)) if (key !== "_storage") out[key] = clean(item); return out;
};
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200)
    throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_INTENT_OWNER_REQUIRED", "Owner recovery-intent audit wajib ditentukan", 400);
}

export function createRecoverySloRetentionDecisionGateRecoveryIntentContinuityService({ store, anchorService, attestationService } = {}) {
  if (!store?.listEvidence || typeof anchorService?.getRecoverySloRetentionDecisionGateAnchorStatus !== "function"
    || typeof attestationService?.verifyRecoverySloRetentionDecisionGateAnchorRecoveryAttestation !== "function")
    throw new TypeError("Recovery-intent continuity membutuhkan store, anchor status, dan attestation verifier");
  function validateTransitions(intent) {
    if (!Array.isArray(intent.transitionHistory) || !intent.transitionHistory.length) return { valid: true, historyNotProven: true, findings: [] };
    let previous = null;
    const findings = [];
    for (let i = 0; i < intent.transitionHistory.length; i++) {
      const event = intent.transitionHistory[i], unsigned = clean(event || {}); delete unsigned.transitionDigest;
      if (!event || event.sequence !== i + 1 || event.previousTransitionDigest !== previous || !DIGEST.test(event.transitionDigest || "")
        || sha256(canonical(unsigned)) !== event.transitionDigest || !["prepared", "anchor_reconciled", "attestation_draft_persisted", "completed", "legacy_history_unproven"].includes(event.phase)
        || !Number.isFinite(Date.parse(event.at))) {
        findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_TRANSITION_CHAIN_INVALID", sequence: event?.sequence ?? i + 1 });
        break;
      }
      previous = event.transitionDigest;
    }
    const phases = intent.transitionHistory.map(event => event?.phase);
    const normalizedPhases = phases.filter(phase => phase !== "legacy_history_unproven");
    const expectedOrder = ["prepared", "anchor_reconciled", "attestation_draft_persisted", "completed"];
    let previousRank = -1;
    for (const phase of normalizedPhases) {
      const rank = expectedOrder.indexOf(phase);
      if (rank < 0 || rank <= previousRank) {
        findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_TRANSITION_ORDER_INVALID", phase });
        break;
      }
      previousRank = rank;
    }
    const last = intent.transitionHistory.at(-1);
    const expected = intent.status === "prepared" ? ["prepared", "legacy_history_unproven"]
      : intent.status === "anchor_reconciled" ? ["anchor_reconciled", "attestation_draft_persisted"]
        : intent.status === "completed" ? ["completed"] : [];
    if (!expected.includes(last?.phase)) findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_PHASE_MISMATCH", status: intent.status, lastPhase: last?.phase || null });
    if (intent.status === "completed" && !normalizedPhases.includes("anchor_reconciled"))
      findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_COMPLETION_WITHOUT_RECONCILIATION" });
    return { valid: findings.length === 0, historyNotProven: Boolean(intent.historyNotProven), findings };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const rows = await store.listEvidence(ownerId);
    const intents = rows.filter(item => item?.kind === INTENT_KIND && item.ownerId === ownerId)
      .sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)) || String(a.id).localeCompare(String(b.id)));
    const findings = [];
    let historyNotProven = false, valid = 0, completed = 0, pending = 0, recoverable = 0;
    const seen = new Set();
    for (const intent of intents) {
      if (seen.has(intent.id)) findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_DUPLICATE_ID", intentId: intent.id });
      seen.add(intent.id);
      if (intent.digest !== digestRecord(intent) || intent.schemaVersion !== 1 || !intent.id || !Number.isFinite(Date.parse(intent.createdAt))
        || !["prepared", "anchor_reconciled", "completed"].includes(intent.status) || typeof intent.reason !== "string"
        || !intent.before || intent.before.status !== "behind_local" || !Number.isSafeInteger(intent.before.total) || intent.before.total < 1
        || !Number.isSafeInteger(intent.before.anchorSequence) || intent.before.anchorSequence < 1 || !DIGEST.test(intent.before.anchorDigest || "")) {
        findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_INVALID", intentId: intent.id || null });
        continue;
      }
      const transition = validateTransitions(intent);
      historyNotProven ||= transition.historyNotProven;
      findings.push(...transition.findings.map(item => ({ ...item, intentId: intent.id })));
      if (intent.status === "prepared") {
        pending++;
        if (intent.after) findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_PREPARED_HAS_AFTER_STATE", intentId: intent.id });
      } else {
        if (!intent.after || intent.after.status !== "anchored" || !Number.isSafeInteger(intent.after.total) || intent.after.total < intent.before.total
          || !Number.isSafeInteger(intent.after.anchorSequence) || intent.after.anchorSequence < intent.before.total
          || !DIGEST.test(intent.after.anchorDigest || "")) {
          findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_AFTER_STATE_INVALID", intentId: intent.id });
          continue;
        }
        if (intent.status === "anchor_reconciled") pending++;
        if (intent.attestationDraft && (!DIGEST.test(intent.attestationDraft.attestationDigest || "")
          || intent.attestationDraft.ownerId !== ownerId || intent.attestationDraft.recovery?.anchorDigest !== intent.after.anchorDigest
          || intent.attestationDraft.recovery?.anchorSequence !== intent.after.anchorSequence)) {
          findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_DRAFT_MISMATCH", intentId: intent.id });
        }
        if (intent.status === "completed") {
          completed++;
          if (!intent.attestation || intent.attestation.recovery?.anchorDigest !== intent.after.anchorDigest
            || intent.attestation.recovery?.anchorSequence !== intent.after.anchorSequence || intent.attestation.ownerId !== ownerId) {
            findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_ATTESTATION_MISMATCH", intentId: intent.id });
          } else {
            try {
              const verification = await attestationService.verifyRecoverySloRetentionDecisionGateAnchorRecoveryAttestation(ownerId, intent.attestation);
              if (!verification.historicallyValid) findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_ATTESTATION_INVALID", intentId: intent.id, verificationFindings: verification.findings || [] });
              else valid++;
            } catch { findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_ATTESTATION_VERIFICATION_FAILED", intentId: intent.id }); }
          }
        }
      }
    }
    if (pending > 1) findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENTS_MULTIPLE_PENDING", count: pending });
    for (let i = 1; i < intents.length; i++) {
      const previous = intents[i - 1], current = intents[i];
      if (previous.status === "completed" && current.before && previous.after) {
        if (current.before.total < previous.after.total || current.before.anchorSequence < previous.after.anchorSequence) {
          findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_TIMELINE_ROLLBACK", previousIntentId: previous.id, intentId: current.id });
        } else if (current.before.anchorSequence === previous.after.anchorSequence && current.before.anchorDigest !== previous.after.anchorDigest) {
          findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_TIMELINE_DIGEST_CONFLICT", previousIntentId: previous.id, intentId: current.id });
        }
      }
    }
    let anchor = null;
    try { anchor = await anchorService.getRecoverySloRetentionDecisionGateAnchorStatus(ownerId); }
    catch { findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_ANCHOR_STATUS_UNAVAILABLE" }); }
    const latest = intents.at(-1);
    if (latest && anchor) {
      if (latest.status === "prepared") {
        if (anchor.status === "anchored" && anchor.anchorSequence >= latest.before.total) recoverable++;
        else if (anchor.status !== "behind_local" || anchor.anchorSequence !== latest.before.anchorSequence || anchor.anchorDigest !== latest.before.anchorDigest) {
          findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_PREPARED_ANCHOR_DISCONTINUITY", intentId: latest.id, anchorStatus: anchor.status });
        }
      } else if (latest.after && (anchor.status !== "anchored" || anchor.anchorSequence < latest.after.anchorSequence)) {
        findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_INTENT_ANCHOR_ROLLBACK", intentId: latest.id, anchorStatus: anchor.status });
      }
    }
    const status = findings.length ? "unhealthy" : recoverable || pending ? "recoverable" : intents.length ? "healthy" : "not_initialized";
    return { status, ownerId, total: intents.length, validAttestations: valid, completed, pending, recoverableInterruptions: recoverable,
      historyNotProven, anchorStatus: anchor?.status || "unavailable", findings, readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ auditRecoverySloRetentionDecisionGateRecoveryIntentContinuity: audit });
}
