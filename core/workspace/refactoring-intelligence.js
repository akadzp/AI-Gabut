import { searchCode } from './project-index.js';
import { findSymbol, findReferences } from './project-index.js';

const MAX_RESULTS = 20;

function normalize(value) {
  return String(value || '').trim();
}

function inferRefactorKind(task = '') {
  const text = task.toLowerCase();
  if (/rename|ubah nama|ganti nama/.test(text)) return 'rename';
  if (/extract|pisahkan|ekstrak/.test(text)) return 'extract';
  if (/inline|gabungkan|satukan/.test(text)) return 'inline';
  if (/move|pindah/.test(text)) return 'move';
  if (/simplif|sederhan|cleanup|rapikan/.test(text)) return 'simplify';
  return 'general';
}

async function resolveTargetSymbol(symbol, path) {
  if (!symbol || !path) return null;
  try {
    const result = await findSymbol(symbol, { path, limit: 10, refresh: false });
    return result;
  } catch {
    return null;
  }
}

export async function planRefactoring({ task, path, symbol, newName, refresh = false } = {}) {
  const cleanTask = normalize(task);
  const cleanPath = normalize(path);
  const cleanSymbol = normalize(symbol);
  const cleanNewName = normalize(newName);

  if (!cleanTask) throw new Error('task wajib diisi');

  const kind = inferRefactorKind(cleanTask);
  const targetFiles = new Set();
  const evidence = [];
  const blockers = [];
  const readBeforeEdit = [];

  if (cleanPath) {
    targetFiles.add(cleanPath);
    readBeforeEdit.push(cleanPath);
  }

  let symbolInfo = null;
  if (cleanSymbol && cleanPath) {
    symbolInfo = await resolveTargetSymbol(cleanSymbol, cleanPath);
    if (!symbolInfo || symbolInfo.matches?.length === 0) {
      blockers.push(`Symbol '${cleanSymbol}' tidak ditemukan secara pasti di ${cleanPath}.`);
    } else {
      evidence.push({ type: 'symbol', path: cleanPath, symbol: cleanSymbol, result: symbolInfo });
      try {
        const refs = await findReferences(cleanSymbol, { path: cleanPath, limit: MAX_RESULTS, refresh });
        for (const item of refs?.references || refs?.matches || []) {
          if (item.path) targetFiles.add(item.path);
        }
        evidence.push({ type: 'references', path: cleanPath, symbol: cleanSymbol, result: refs });
      } catch (error) {
        blockers.push(`Reference analysis gagal: ${error.message}`);
      }
    }
  }

  if (cleanTask) {
    try {
      const search = await searchCode(cleanTask, { limit: 10, refresh, caseSensitive: false, regex: false });
      for (const item of search?.matches || search?.results || []) {
        if (item.path) targetFiles.add(item.path);
      }
      evidence.push({ type: 'task-search', result: search });
    } catch {
      // Task search is advisory; no blocker needed.
    }
  }

  if (kind === 'rename' && cleanSymbol && !cleanNewName) {
    blockers.push('Rename refactoring membutuhkan newName agar perubahan dapat direncanakan secara eksplisit.');
  }

  const verification = [];
  if (targetFiles.size) verification.push('Re-run targeted syntax/test checks for affected files.');
  if (cleanSymbol) verification.push(`Re-check references for '${cleanNewName || cleanSymbol}' after the edit.`);
  if (kind === 'move') verification.push('Verify import resolution for moved module and its dependents.');
  if (kind === 'extract') verification.push('Verify extracted symbol binding and call sites.');

  return {
    ok: blockers.length === 0,
    readOnly: true,
    kind,
    task: cleanTask,
    target: { path: cleanPath || null, symbol: cleanSymbol || null, newName: cleanNewName || null },
    affectedFiles: [...targetFiles].slice(0, MAX_RESULTS),
    readBeforeEdit: [...new Set(readBeforeEdit)].slice(0, MAX_RESULTS),
    evidence,
    blockers,
    verification,
    constraints: [
      'No files are modified by plan_refactoring.',
      'Refactoring must use edit_file with the current file hash.',
      'Broad or ambiguous refactors require additional inspection before editing.'
    ]
  };
}
