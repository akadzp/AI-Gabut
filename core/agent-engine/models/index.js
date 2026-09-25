import { chatWithOpenAI, listOpenAIModels } from "./openai.js";
import { chatWithGemini, listGeminiModels } from "./gemini.js";

export async function listModels(provider) {
  if (provider === "openai") {
    return listOpenAIModels();
  }

  if (provider === "gemini") {
    return listGeminiModels();
  }

  throw new Error(`Provider tidak dikenal: ${provider}`);
}

export async function chatWithProvider({ provider, model, messages }) {
  const selected = provider || process.env.AI_PROVIDER || "openai";

  if (selected === "openai") {
    return chatWithOpenAI({ model, messages });
  }

  if (selected === "gemini") {
    return chatWithGemini({ model, messages });
  }

  throw new Error(`Provider tidak dikenal: ${selected}`);
}
