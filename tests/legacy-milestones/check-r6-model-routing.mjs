import assert from 'node:assert/strict';
import { routeModel, getModelCandidates } from '../../core/agent-engine/models/model-router.js';

const previous = {
  models: process.env.AI_ROUTER_MODELS,
  openai: process.env.OPENAI_MODEL,
  gemini: process.env.GEMINI_MODEL
};

try {
  process.env.AI_ROUTER_MODELS = JSON.stringify([
    { provider: 'openai', model: 'gpt-fast', capabilities: ['general', 'coding', 'analysis'], maxContextTokens: 10000, latencyMs: 700, inputCost: 1, outputCost: 2, tags: ['fast'] },
    { provider: 'gemini', model: 'gemini-reasoning', capabilities: ['general', 'coding', 'planning', 'analysis', 'deep-reasoning', 'debugging'], maxContextTokens: 10000, latencyMs: 2500, inputCost: 2, outputCost: 8, tags: ['reasoning'] }
  ]);

  const candidates = getModelCandidates();
  assert.equal(candidates.length, 2);

  const coding = routeModel({ prompt: 'Implement a broad architecture refactor and debug the failing tests.' });
  assert.equal(coding.ok, true);
  assert.equal(coding.mode, 'automatic');
  assert.equal(coding.provider, 'gemini');
  assert.equal(coding.model, 'gemini-reasoning');
  assert.equal(coding.fallbackCandidates.length, 1);

  const explicit = routeModel({ prompt: 'quick check', provider: 'openai', model: 'gpt-fast' });
  assert.equal(explicit.mode, 'explicit');
  assert.equal(explicit.provider, 'openai');
  assert.equal(explicit.model, 'gpt-fast');

  const oversized = routeModel({ prompt: 'deep reasoning', messages: [{ role: 'user', content: 'x'.repeat(50000) }] });
  assert.equal(oversized.ok, false);

  console.log('R6 MODEL ROUTING CHECK PASSED');
} finally {
  if (previous.models === undefined) delete process.env.AI_ROUTER_MODELS; else process.env.AI_ROUTER_MODELS = previous.models;
  if (previous.openai === undefined) delete process.env.OPENAI_MODEL; else process.env.OPENAI_MODEL = previous.openai;
  if (previous.gemini === undefined) delete process.env.GEMINI_MODEL; else process.env.GEMINI_MODEL = previous.gemini;
}
