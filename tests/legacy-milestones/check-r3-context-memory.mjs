import assert from "node:assert/strict";
import { prepareContext, compactContextForActivity } from "../../core/agent-engine/context/context-intelligence.js";
import { createMemoryStore, addMemories } from "../../core/agent-engine/context/memory.js";

const memories = createMemoryStore();
addMemories(memories, [
  { type: "project_rule", content: "Mulai sekarang gunakan incremental ZIP untuk milestone agent.", importance: 0.95, topic: "workspace" },
  { type: "decision", content: "GitHub adalah integration, bukan capability coding.", importance: 0.9, topic: "git-approval" },
  { type: "fact", content: "Agentic roadmap memiliki 10 roadmap besar.", importance: 0.8, topic: "memory" }
]);

const prepared = prepareContext({
  prompt: "Bagaimana aturan milestone agent dan GitHub integration?",
  conversation: [
    { role: "user", content: "Kita membangun Agent bertahap." },
    { role: "assistant", content: "Saya akan menggunakan capability yang terpisah dari integration." },
    { role: "user", content: "Jangan campurkan GitHub dengan coding capability." }
  ],
  memories,
  charBudget: 12000,
  memoryLimit: 5,
  recentMessages: 2
});

assert.equal(prepared.conversation.length, 2);
assert.ok(prepared.memories.length >= 1);
assert.ok(prepared.memoryMatches.some(item => item.memory.content.includes("GitHub")));
assert.ok(prepared.budget.estimatedTokens <= prepared.budget.maxEstimatedTokens);
assert.equal(compactContextForActivity(prepared).relevantMemories, prepared.memories.length);

console.log(`R3 Context & Memory Intelligence: OK (${prepared.memories.length} relevant memories)`);
