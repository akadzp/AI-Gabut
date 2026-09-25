import { GoogleGenAI } from "@google/genai";

let client;

function getClient() {
  if (!process.env.GEMINI_API_KEY) {
    throw new Error("GEMINI_API_KEY belum di-set");
  }

  client ??= new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY
  });

  return client;
}

export async function listGeminiModels() {
  const pager = await getClient().models.list();
  const models = [];

  for await (const model of pager) {
    const actions = model.supportedActions ?? [];

    if (!actions.includes("generateContent")) {
      continue;
    }

    // Gemini API returns resource names such as "models/gemini-2.5-flash".
    // generateContent accepts the model ID without the "models/" prefix.
    const id = (model.name ?? "").replace(/^models\//, "");

    if (!id) continue;

    models.push({
      id,
      name: model.displayName || id,
      description: model.description || null,
      inputTokenLimit: model.inputTokenLimit ?? null,
      outputTokenLimit: model.outputTokenLimit ?? null
    });
  }

  return models;
}

export async function chatWithGemini({ messages, model }) {
  const selectedModel = model || process.env.GEMINI_MODEL;

  if (!selectedModel) {
    throw new Error("Model Gemini belum dipilih");
  }

  const prompt = messages
    .map(message => `${message.role.toUpperCase()}: ${message.content}`)
    .join("\n\n");

  const response = await getClient().models.generateContent({
    model: selectedModel,
    contents: prompt
  });

  return {
    text: response.text ?? "",
    raw: response,
    model: selectedModel
  };
}
