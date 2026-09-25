import fs from "node:fs/promises";
import path from "node:path";

const root = path.resolve("core");
const jsFiles = [];

async function walk(dir) {
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) await walk(full);
    else if (entry.name.endsWith(".js")) jsFiles.push(full);
  }
}

await walk(root);

const violations = [];
const forbidden = new Map([
  ["security", ["platform", "agent-engine", "storage", "sync", "linux", "media", "workspace", "tasks", "api", "system"]],
]);

for (const file of jsFiles) {
  const text = await fs.readFile(file, "utf8");
  const rel = path.relative(root, file).split(path.sep);
  const owner = rel[0];
  const imports = [...text.matchAll(/(?:from\s+|import\s*\(|require\()\s*["']([^"']+)["']/g)].map(m => m[1]);
  for (const spec of imports) {
    if (!spec.startsWith(".")) continue;
    const target = path.resolve(path.dirname(file), spec);
    const targetRel = path.relative(root, target).split(path.sep);
    const targetOwner = targetRel[0];
    if (forbidden.get(owner)?.includes(targetOwner)) {
      violations.push(`${path.relative(process.cwd(), file)} -> ${targetOwner} (${spec})`);
    }
  }
}

if (violations.length) {
  console.error("ARCHITECTURE CHECK FAILED");
  for (const violation of violations) console.error(" -", violation);
  process.exit(1);
}

console.log(`ARCHITECTURE CHECK PASS — ${jsFiles.length} JavaScript files`);
