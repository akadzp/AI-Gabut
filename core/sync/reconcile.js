import { diffSnapshots } from "./diff.js";
import { normalizeSnapshot } from "./contracts.js";

function sameHash(a, b) {
  return Boolean(a && b && a === b);
}

export function planReconciliation({ base, local, remote, strategy = "manual" } = {}) {
  const baseline = normalizeSnapshot(base);
  const left = normalizeSnapshot(local);
  const right = normalizeSnapshot(remote);
  const keys = [...new Set([...Object.keys(baseline.resources), ...Object.keys(left.resources), ...Object.keys(right.resources)])].sort();
  const changes = [];
  for (const key of keys) {
    const b = baseline.resources[key];
    const l = left.resources[key];
    const r = right.resources[key];
    const localChanged = (b?.hash || null) !== (l?.hash || null);
    const remoteChanged = (b?.hash || null) !== (r?.hash || null);
    let type = "unchanged";
    let action = "none";
    let conflict = false;
    if (localChanged && remoteChanged && !sameHash(l?.hash, r?.hash)) {
      type = "conflict"; conflict = true; action = strategy === "local" ? "use-local" : strategy === "remote" ? "use-remote" : "manual";
    } else if (remoteChanged) {
      type = r ? (b ? "update" : "create") : "delete"; action = "apply-remote";
    } else if (localChanged) {
      type = l ? (b ? "update" : "create") : "delete"; action = "preserve-local";
    }
    changes.push({ key, type, action, conflict, base: b?.value ?? null, local: l?.value ?? null, remote: r?.value ?? null, baseHash: b?.hash || null, localHash: l?.hash || null, remoteHash: r?.hash || null });
  }
  return {
    strategy,
    baseSource: baseline.source,
    localSource: left.source,
    remoteSource: right.source,
    changes,
    conflicts: changes.filter(item => item.conflict),
    counts: {
      total: changes.length,
      conflicts: changes.filter(item => item.conflict).length,
      applyRemote: changes.filter(item => item.action === "apply-remote").length,
      preserveLocal: changes.filter(item => item.action === "preserve-local").length,
      manual: changes.filter(item => item.action === "manual").length
    }
  };
}

export function applyReconciliationPlan(plan, { readOnly = false, apply = null } = {}) {
  if (!plan || typeof plan !== "object") throw new TypeError("Reconciliation plan wajib diisi");
  if (plan.conflicts?.length && plan.strategy === "manual") return { ok: false, applied: [], blocked: plan.conflicts, reason: "conflicts-require-resolution" };
  if (readOnly) return { ok: true, applied: [], blocked: [], dryRun: true };
  if (typeof apply !== "function") return { ok: false, applied: [], blocked: plan.conflicts || [], reason: "apply adapter wajib diinjeksikan" };
  return apply(plan);
}
