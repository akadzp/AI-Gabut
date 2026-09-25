import assert from "node:assert/strict";
import { analyzeSourceSemantics } from "../../core/workspace/semantic-parser.js";

const source = `import { readFile as read } from "./files.js";
export function loadProject(path) {
  return read(path);
}
const result = loadProject("x");
`;

const result = analyzeSourceSemantics(source, ".js");
assert.ok(Array.isArray(result.symbols));
assert.ok(result.symbols.some(item => item.name === "loadProject" && item.kind === "function"));
assert.ok(result.imports.some(item => item.source === "./files.js"));
assert.ok(result.references.some(item => item.name === "loadProject"));
assert.ok(result.references.some(item => item.name === "read"));
console.log(`AST/Semantic Intelligence: OK (${result.parser})`);
