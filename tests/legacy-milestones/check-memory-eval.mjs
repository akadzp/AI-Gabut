import assert from "node:assert/strict";
import {
  createMemoryStore,
  addMemories,
  retrieveMemoryMatches,
  archiveMemory,
  getActiveMemories,
  resolveMemoryConflicts,
  scoreMemory
} from "../../core/agent-engine/context/memory.js";

function test(name, fn) {
  fn();
  console.log(`PASS: ${name}`);
}

test("retrieval selects relevant memory over unrelated memory", () => {
  const store = createMemoryStore([
    { type: "project_rule", content: "AI-Gabut wajib meminta approval sebelum commit atau push.", importance: 1, topic: "git-approval" },
    { type: "fact", content: "Web chat berada di folder public.", importance: 0.7, topic: "frontend" },
    { type: "decision", content: "Backend menggunakan Express.", importance: 0.9, topic: "backend" }
  ]);
  const matches = retrieveMemoryMatches(store, "aturan approval commit push", 3);
  assert.equal(matches.length > 0, true);
  assert.match(matches[0].memory.content, /approval/i);
});

test("irrelevant query does not retrieve weak matches", () => {
  const store = createMemoryStore([
    { type: "project_rule", content: "AI-Gabut wajib meminta approval sebelum commit atau push.", importance: 1, topic: "git-approval" },
    { type: "fact", content: "Web chat berada di folder public.", importance: 0.7, topic: "frontend" }
  ]);
  assert.deepEqual(retrieveMemoryMatches(store, "resep nasi goreng", 5), []);
});

test("superseded memory is excluded from retrieval", () => {
  const store = createMemoryStore([
    { type: "decision", content: "Backend menggunakan Express.", importance: 0.9, topic: "backend", createdAt: "2026-09-25T10:00:00.000Z", updatedAt: "2026-09-25T10:00:00.000Z" },
    { type: "decision", content: "Sekarang backend menggunakan Fastify.", importance: 0.95, topic: "backend", createdAt: "2026-09-25T11:00:00.000Z", updatedAt: "2026-09-25T11:00:00.000Z" }
  ]);
  const result = resolveMemoryConflicts(store);
  assert.equal(result.active.length, 1);
  assert.match(result.active[0].content, /Fastify/);
  const matches = retrieveMemoryMatches(store, "backend framework", 5);
  assert.equal(matches.some(item => /Express/.test(item.memory.content)), false);
});

test("archive removes memory from normal retrieval", () => {
  const store = createMemoryStore([
    { type: "decision", content: "Backend menggunakan Fastify.", importance: 0.9, topic: "backend" }
  ]);
  const memory = getActiveMemories(store)[0];
  archiveMemory(store, memory.id);
  assert.equal(getActiveMemories(store).length, 0);
  assert.deepEqual(retrieveMemoryMatches(store, "backend Fastify", 5), []);
});

test("explicit update supersedes the previous decision", () => {
  const store = createMemoryStore();
  addMemories(store, [{ type: "decision", content: "Backend menggunakan Express.", importance: 0.9, topic: "backend" }]);
  const result = addMemories(store, [{ type: "decision", content: "Mulai sekarang backend menggunakan Fastify.", importance: 0.95, topic: "backend" }]);
  assert.equal(result.superseded.length, 1);
  assert.equal(getActiveMemories(store).length, 1);
  assert.match(getActiveMemories(store)[0].content, /Fastify/);
});

test("importance and recency can break a close relevance tie", () => {
  const now = Date.parse("2026-09-25T12:00:00.000Z");
  const old = { type: "fact", content: "Project menggunakan Node.js untuk backend.", importance: 0.6, topic: "backend", updatedAt: "2026-07-01T12:00:00.000Z" };
  const fresh = { ...old, importance: 0.9, updatedAt: "2026-09-25T11:59:00.000Z" };
  const oldScore = scoreMemory(old, "backend Node.js", now);
  const freshScore = scoreMemory(fresh, "backend Node.js", now);
  assert.equal(freshScore.factors.recency > oldScore.factors.recency, true);
  assert.equal(freshScore.score > oldScore.score, true);
});

test("duplicate memory does not multiply active entries", () => {
  const store = createMemoryStore();
  addMemories(store, [{ type: "project_rule", content: "Commit membutuhkan approval.", importance: 0.95, topic: "git-approval" }]);
  const result = addMemories(store, [{ type: "project_rule", content: "Commit membutuhkan approval.", importance: 0.95, topic: "git-approval" }]);
  assert.equal(result.added.length, 0);
  assert.equal(getActiveMemories(store).length, 1);
});

console.log("\nMemory Evaluation: ALL TESTS PASSED");
