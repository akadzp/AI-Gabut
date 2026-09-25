const chat = document.querySelector("#chat");
const form = document.querySelector("#chat-form");
const promptInput = document.querySelector("#prompt");
const providerInput = document.querySelector("#provider");
const modelInput = document.querySelector("#model");
const sendButton = document.querySelector("#send");

const SESSION_KEY = "ai-gabut-session-id";
let sessionId = localStorage.getItem(SESSION_KEY) || crypto.randomUUID();
localStorage.setItem(SESSION_KEY, sessionId);

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  const original = button.textContent;
  button.textContent = "Tersalin ✓";
  setTimeout(() => { button.textContent = original; }, 1200);
}

function selectMessageText(body) {
  const selection = window.getSelection();
  const range = document.createRange();
  range.selectNodeContents(body);
  selection.removeAllRanges();
  selection.addRange(range);
}

function formatDuration(ms) {
  if (!Number.isFinite(ms)) return "";
  if (ms < 1000) return `${Math.max(1, Math.round(ms))} ms`;
  return `${(ms / 1000).toFixed(1)} detik`;
}

function activityIcon(status) {
  if (status === "completed") return "✓";
  if (status === "error") return "!";
  return "…";
}

function createAssistantMessage() {
  const item = document.createElement("div");
  item.className = "message assistant";

  const header = document.createElement("div");
  header.className = "message-header";
  const label = document.createElement("strong");
  label.textContent = "AI";
  const actions = document.createElement("div");
  actions.className = "message-actions";
  header.append(label, actions);

  const activity = document.createElement("details");
  activity.className = "activity";
  activity.open = true;
  const summary = document.createElement("summary");
  summary.textContent = "Working on your request";
  const activityList = document.createElement("div");
  activityList.className = "activity-list";
  activity.append(summary, activityList);

  const body = document.createElement("pre");
  body.className = "message-body";
  body.textContent = "";
  body.tabIndex = 0;

  const footer = document.createElement("div");
  footer.className = "message-footer";
  const elapsed = document.createElement("span");
  elapsed.className = "elapsed";
  const workspace = document.createElement("span");
  workspace.className = "workspace-state";
  footer.append(elapsed, workspace);

  item.append(header, activity, body, footer);
  chat.appendChild(item);
  chat.scrollTop = chat.scrollHeight;

  return { item, actions, activity, activityList, body, elapsed, workspace, activities: new Map() };
}

function setActivity(view, event) {
  const id = event.id || `activity-${view.activities.size + 1}`;
  let row = view.activities.get(id);
  if (!row) {
    row = document.createElement("div");
    row.className = "activity-row";
    const icon = document.createElement("span");
    icon.className = "activity-icon";
    const text = document.createElement("span");
    text.className = "activity-text";
    const time = document.createElement("span");
    time.className = "activity-time";
    row.append(icon, text, time);
    view.activityList.appendChild(row);
    view.activities.set(id, row);
  }

  const [icon, text, time] = row.children;
  row.dataset.status = event.status || "running";
  icon.textContent = activityIcon(event.status);
  text.textContent = event.label || event.action || "Working";
  time.textContent = event.durationMs != null ? formatDuration(event.durationMs) : "";

  if (event.status === "error" && event.error) {
    text.title = event.error;
  }
  chat.scrollTop = chat.scrollHeight;
}

function finishAssistant(view, data) {
  view.body.textContent = data.text || "(tidak ada respons)";
  view.elapsed.textContent = `Selesai dalam ${formatDuration(data.durationMs)}.`;

  if (data.workspaceState?.files) {
    const files = data.workspaceState.files;
    const total = files.staged.length + files.unstaged.length + files.untracked.length;
    view.workspace.textContent = `${data.workspaceState.branch || "Git"} · ${total} perubahan/berkas belum bersih`;
  }

  const selectButton = document.createElement("button");
  selectButton.type = "button";
  selectButton.className = "message-action";
  selectButton.textContent = "Pilih semua";
  selectButton.addEventListener("click", () => selectMessageText(view.body));

  const copyButton = document.createElement("button");
  copyButton.type = "button";
  copyButton.className = "message-action";
  copyButton.textContent = "Salin";
  copyButton.addEventListener("click", () => copyText(view.body.textContent, copyButton));
  view.actions.append(selectButton, copyButton);

  view.activity.open = false;
  chat.scrollTop = chat.scrollHeight;
}

function addUserMessage(text) {
  const item = document.createElement("div");
  item.className = "message user";
  const header = document.createElement("div");
  header.className = "message-header";
  const label = document.createElement("strong");
  label.textContent = "You";
  header.append(label);
  const body = document.createElement("pre");
  body.className = "message-body";
  body.textContent = text;
  body.tabIndex = 0;
  item.append(header, body);
  chat.appendChild(item);
  chat.scrollTop = chat.scrollHeight;
}

async function loadModels() {
  const provider = providerInput.value;
  modelInput.disabled = true;
  modelInput.replaceChildren(new Option("Mengambil model dari API...", ""));
  try {
    const response = await fetch(`/api/models?provider=${encodeURIComponent(provider)}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Gagal mengambil model");
    modelInput.replaceChildren();
    if (!data.models.length) {
      modelInput.add(new Option("Tidak ada model tersedia", ""));
      return;
    }
    for (const model of data.models) {
      modelInput.add(new Option(model.name || model.id, model.id));
    }
    modelInput.disabled = false;
  } catch (error) {
    modelInput.replaceChildren(new Option("Gagal memuat model", ""));
    modelInput.disabled = true;
    addUserMessage(`Tidak bisa mengambil daftar model ${provider}. ${error.message}`);
  }
}

async function consumeChatStream(payload, view) {
  const response = await fetch("/api/chat/stream", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    let message = "Request gagal";
    try { message = (await response.json()).error || message; } catch {}
    throw new Error(message);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let result = null;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      if (!line.trim()) continue;
      const event = JSON.parse(line);
      if (event.type === "session") {
        sessionId = event.sessionId;
        localStorage.setItem(SESSION_KEY, sessionId);
      } else if (event.type === "activity") {
        setActivity(view, event);
      } else if (event.type === "result") {
        result = event;
      } else if (event.type === "error") {
        throw new Error(event.error || "Agent gagal");
      }
    }
  }

  if (buffer.trim()) {
    const event = JSON.parse(buffer);
    if (event.type === "result") result = event;
    if (event.type === "error") throw new Error(event.error || "Agent gagal");
  }

  if (!result) throw new Error("Server menutup stream tanpa hasil");
  return result;
}

providerInput.addEventListener("change", loadModels);
addUserMessage("M7.0 aktif. Agent sekarang memiliki memory lifecycle, retrieval, Git/workspace state, activity stream, dan Project Intelligence.");
loadModels();

form.addEventListener("submit", async event => {
  event.preventDefault();
  const prompt = promptInput.value.trim();
  const model = modelInput.value;
  if (!prompt || !model) return;

  addUserMessage(prompt);
  promptInput.value = "";
  sendButton.disabled = true;
  const view = createAssistantMessage();
  const clientStarted = performance.now();

  try {
    const data = await consumeChatStream({
      prompt,
      provider: providerInput.value,
      model,
      sessionId
    }, view);
    data.durationMs = Number.isFinite(data.durationMs) ? data.durationMs : performance.now() - clientStarted;
    finishAssistant(view, data);
  } catch (error) {
    view.body.textContent = `Error: ${error.message}`;
    view.elapsed.textContent = `Berhenti setelah ${formatDuration(performance.now() - clientStarted)}.`;
    view.activity.open = true;
  } finally {
    sendButton.disabled = false;
    promptInput.focus();
  }
});
