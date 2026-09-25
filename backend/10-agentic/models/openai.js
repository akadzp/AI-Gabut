import OpenAI from "openai";

let client;

function getClient() {
  if (!process.env.OPENAI_API_KEY) {
    throw new Error("OPENAI_API_KEY belum di-set");
  }

  client ??= new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
  });

  return client;
}

export async function listOpenAIModels() {
  const response = await getClient().models.list();

  return response.data
    .map(model => ({
      id: model.id,
      name: model.id,
      owner: model.owned_by ?? null,
      created: model.created ?? null
    }))
    .filter(model => Boolean(model.id))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export async function chatWithOpenAI({ messages, model }) {
  const selectedModel = model || process.env.OPENAI_MODEL;

  if (!selectedModel) {
    throw new Error("Model OpenAI belum dipilih");
  }

  const response = await getClient().responses.create({
    model: selectedModel,
    input: messages
  });

  return {
    text: response.output_text ?? "",
    raw: response,
    model: selectedModel
  };
}
