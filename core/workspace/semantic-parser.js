let babelParse = null;
try {
  ({ parse: babelParse } = await import("@babel/parser"));
} catch {
  babelParse = null;
}


function parseAst(content, extension = ".js") {
  const plugins = ["jsx", "typescript", "classProperties", "classPrivateProperties", "classPrivateMethods", "topLevelAwait", "dynamicImport", "importMeta"];
  if (!babelParse) return null;
  try {
    return babelParse(content, {
      sourceType: "unambiguous",
      errorRecovery: true,
      ranges: false,
      plugins: extension === ".json" ? [] : plugins
    });
  } catch {
    return null;
  }
}

function walkAst(node, visit, parent = null) {
  if (!node || typeof node !== "object") return;
  if (node.type) visit(node, parent);
  for (const [key, value] of Object.entries(node)) {
    if (key === "loc" || key === "start" || key === "end") continue;
    if (Array.isArray(value)) {
      for (const child of value) if (child?.type) walkAst(child, visit, node);
    } else if (value?.type) {
      walkAst(value, visit, node);
    }
  }
}


function lexicalSemantics(content) {
  const symbols = [];
  const imports = [];
  const references = [];
  const clean = content
    .replace(/\/\*[\s\S]*?\*\//g, match => match.replace(/[^\n]/g, " "))
    .replace(/(^|\s)\/\/.*$/gm, "$1");
  const lineOf = index => clean.slice(0, index).split(/\n/).length;
  const add = (name, kind, index) => symbols.push({ name, kind, line: lineOf(index), column: index - clean.lastIndexOf("\n", index - 1) });
  for (const match of clean.matchAll(/\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/g)) add(match[1], "function", match.index);
  for (const match of clean.matchAll(/\b(?:export\s+)?class\s+([A-Za-z_$][\w$]*)/g)) add(match[1], "class", match.index);
  for (const match of clean.matchAll(/\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)/g)) add(match[1], "variable", match.index);
  for (const match of clean.matchAll(/\bimport\s+(?:[\s\S]*?\s+from\s+)?["']([^"']+)["']/g)) imports.push({ source: match[1], line: lineOf(match.index), kind: "import" });
  for (const match of clean.matchAll(/\b([A-Za-z_$][\w$]*)\b/g)) references.push({ name: match[1], line: lineOf(match.index), column: match.index - clean.lastIndexOf("\n", match.index - 1) });
  return { symbols: [...new Map(symbols.map(item => [`${item.name}:${item.kind}:${item.line}`, item])).values()], imports, references, parseable: false, parser: "lexical-fallback" };
}

export function analyzeSourceSemantics(content, extension = ".js") {
  const ast = parseAst(content, extension);
  if (!ast) return lexicalSemantics(content);
  const symbols = [];
  const imports = [];
  const references = [];
  const declarationNodes = new Set();
  const pushSymbol = (name, kind, node) => {
    if (!name || !node?.loc) return;
    symbols.push({ name, kind, line: node.loc.start.line, column: node.loc.start.column + 1 });
    declarationNodes.add(node);
  };

  walkAst(ast, (node, parent) => {
    if (node.type === "ImportDeclaration") {
      imports.push({ source: node.source?.value || "", line: node.loc?.start.line || null, kind: "import" });
      return;
    }
    if (node.type === "FunctionDeclaration" || node.type === "ClassDeclaration") {
      pushSymbol(node.id?.name, node.type === "FunctionDeclaration" ? "function" : "class", node);
      return;
    }
    if (node.type === "VariableDeclarator" && node.id?.type === "Identifier") {
      pushSymbol(node.id.name, "variable", node);
      return;
    }
    if (node.type === "ExportDefaultDeclaration") {
      if (node.declaration?.type === "FunctionDeclaration" || node.declaration?.type === "ClassDeclaration") {
        pushSymbol(node.declaration.id?.name || "default", "default-export", node);
      }
      return;
    }
    if (node.type === "ExportNamedDeclaration") {
      for (const spec of node.specifiers || []) {
        const name = spec.exported?.name || spec.exported?.value;
        if (name) pushSymbol(name, "export", spec);
      }
    }
    if (node.type === "Identifier" && node.loc) {
      if (parent?.type === "MemberExpression" && parent.property === node && !parent.computed) return;
      if (parent?.type === "ObjectProperty" && parent.key === node && !parent.computed) return;
      if (parent?.type === "ObjectMethod" && parent.key === node && !parent.computed) return;
      references.push({ name: node.name, line: node.loc.start.line, column: node.loc.start.column + 1 });
    }
  });

  const uniqueSymbols = [...new Map(symbols.map(item => [`${item.name}:${item.kind}:${item.line}`, item])).values()];
  return { symbols: uniqueSymbols, imports, references, parseable: true, parser: "babel" };
}

