import { readdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";

async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...await walk(full));
    else if (entry.name.endsWith(".js")) files.push(full);
  }
  return files;
}

const files = await walk("core");
let failed = false;

for (const file of files) {
  const result = await new Promise(resolve => {
    const child = spawn(process.execPath, ["--check", file], {
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stderr = "";
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.on("close", code => resolve({ code, stderr }));
  });

  if (result.code !== 0) {
    failed = true;
    console.error(`FAIL ${file}\n${result.stderr}`);
  } else {
    console.log(`OK   ${file}`);
  }
}

if (failed) process.exit(1);
