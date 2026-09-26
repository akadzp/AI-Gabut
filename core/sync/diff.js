import { CHANGE_TYPES, normalizeSnapshot } from "./contracts.js";

export function diffSnapshots(base, remote) {
  const left = normalizeSnapshot(base);
  const right = normalizeSnapshot(remote);
  const keys = [...new Set([...Object.keys(left.resources), ...Object.keys(right.resources)])].sort();
  const changes = [];
  for (const key of keys) {
    const a = left.resources[key];
    const b = right.resources[key];
    let type = "unchanged";
    if (!a && b) type = "create";
    else if (a && !b) type = "delete";
    else if (a?.hash !== b?.hash) type = "update";
    changes.push({
      key,
      type,
      baseHash: a?.hash || null,
      remoteHash: b?.hash || null,
      base: a?.value ?? null,
      remote: b?.value ?? null
    });
  }
  return { source: right.source, changes, counts: Object.fromEntries(CHANGE_TYPES.map(type => [type, changes.filter(item => item.type === type).length])) };
}
