import assert from "node:assert/strict";
import { createMemoryStore, addMemories, retrieveMemories, archiveMemory, resolveMemoryConflicts } from "../../core/agent-engine/context/memory.js";

const store = createMemoryStore();
let result = addMemories(store, [{
  type: "decision",
  content: "Untuk sementara backend menggunakan Express.",
  importance: 0.9,
  topic: "backend"
}]);
assert.equal(result.added.length, 1);
assert.equal(store[0].status, "active");

result = addMemories(store, [{
  type: "decision",
  content: "Mulai sekarang backend project menggunakan Fastify.",
  importance: 0.9,
  topic: "backend"
}]);
assert.equal(result.superseded.length, 1);
assert.equal(store.filter(item => item.status === "active").length, 1);
assert.match(retrieveMemories(store, "framework backend Fastify")[0].content, /Fastify/);
assert.equal(retrieveMemories(store, "framework backend Express").some(item => /Express/.test(item.content)), false);

const active = store.find(item => item.status === "active");
archiveMemory(store, active.id);
assert.equal(retrieveMemories(store, "backend Fastify").length, 0);

console.log("memory lifecycle: OK");


const conflictStore = createMemoryStore([
  {
    type: "decision",
    content: "Backend menggunakan Express.",
    importance: 0.9,
    topic: "backend",
    createdAt: "2026-09-25T10:00:00.000Z",
    updatedAt: "2026-09-25T10:00:00.000Z"
  },
  {
    type: "decision",
    content: "Sekarang backend menggunakan Fastify.",
    importance: 0.9,
    topic: "backend",
    createdAt: "2026-09-25T11:00:00.000Z",
    updatedAt: "2026-09-25T11:00:00.000Z"
  }
]);
const conflictResult = resolveMemoryConflicts(conflictStore);
assert.equal(conflictResult.active.length, 1);
assert.match(conflictResult.active[0].content, /Fastify/);
assert.equal(conflictResult.resolved.length, 1);
assert.equal(conflictStore.find(item => /Express/.test(item.content)).status, "superseded");

const archived = conflictStore.find(item => /Express/.test(item.content));
assert.equal(archived.supersessionReason, "conflict-resolution");

console.log("memory conflict resolution: OK");

import { retrieveMemoryMatches, scoreMemory } from "../../core/agent-engine/context/memory.js";

const retrievalStore = createMemoryStore([
  {
    type: "project_rule",
    content: "AI-Gabut wajib meminta approval sebelum commit atau push.",
    importance: 1,
    topic: "git-approval",
    createdAt: "2026-09-25T11:55:00.000Z",
    updatedAt: "2026-09-25T11:55:00.000Z"
  },
  {
    type: "fact",
    content: "Project memiliki halaman web chat di folder public.",
    importance: 0.7,
    topic: "frontend",
    createdAt: "2026-09-25T11:55:00.000Z",
    updatedAt: "2026-09-25T11:55:00.000Z"
  },
  {
    type: "decision",
    content: "Backend menggunakan Express untuk server AI-Gabut.",
    importance: 0.9,
    topic: "backend",
    createdAt: "2026-08-01T11:55:00.000Z",
    updatedAt: "2026-08-01T11:55:00.000Z"
  }
]);

const gitMatches = retrieveMemoryMatches(retrievalStore, "aturan approval commit push", 3);
assert.equal(gitMatches.length >= 1, true);
assert.match(gitMatches[0].memory.content, /approval/i);
assert.equal(gitMatches[0].factors.topic, 1);
assert.equal(gitMatches[0].factors.lexical > 0, true);

const frontendMatches = retrieveMemoryMatches(retrievalStore, "struktur web chat public", 3);
assert.equal(frontendMatches.length >= 1, true);
assert.match(frontendMatches[0].memory.content, /public/i);

const oldBackendScore = scoreMemory(retrievalStore[2], "backend Express", Date.parse("2026-09-25T12:00:00.000Z"));
const freshBackendScore = scoreMemory({
  ...retrievalStore[2],
  updatedAt: "2026-09-25T11:59:00.000Z"
}, "backend Express", Date.parse("2026-09-25T12:00:00.000Z"));
assert.equal(freshBackendScore.factors.recency > oldBackendScore.factors.recency, true);

const irrelevantMatches = retrieveMemoryMatches(retrievalStore, "resep nasi goreng", 3);
assert.equal(irrelevantMatches.length, 0);

console.log("memory retrieval scoring: OK");
