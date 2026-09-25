import {
  readWorkspaceFile,
  writeWorkspaceFile,
  listWorkspaceFiles
} from "../../workspace/manager.js";
import { inspectProject, searchWorkspace, searchCode, findSymbol, findReferences, findReferencesToFile, getDependencyGraph, analyzeImpact, inspectCodeSemantics, findSemanticReferences } from "../../workspace/project-index.js";
import { resolveSymbolBinding, getCallGraph } from "../../workspace/binding-analysis.js";
import { planChange } from "../../workspace/change-planner.js";
import { safeEditFile } from "../../workspace/safe-editor.js";
import { planVerification } from "../../workspace/verification-planner.js";
import { executeVerification } from "../../workspace/verification-executor.js";
import { analyzeTestIntelligence } from "../../workspace/test-intelligence.js";
import { diagnoseVerificationFailure } from "../../workspace/debugging-intelligence.js";
import { planRefactoring } from "../../workspace/refactoring-intelligence.js";
import { analyzeContracts } from "../../workspace/contract-intelligence.js";
import { analyzeSchemas } from "../../workspace/schema-intelligence.js";
import { analyzeFrameworks } from "../../workspace/framework-intelligence.js";
import { planMigration } from "../../workspace/migration-intelligence.js";
import { reviewChangeSet } from "../../workspace/change-set-review.js";

export const workspaceTools = {
  list_files: {
    name: "list_files",
    description: "List files and directories inside the workspace.",
    inputSchema: { type: "object", properties: {} }
  },

  read_file: {
    name: "read_file",
    description: "Read a UTF-8 text file inside the workspace.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"]
    }
  },

  edit_file: {
    name: "edit_file",
    description: "Safely edit an existing text file using an expected SHA-256 hash and exact text operation. Refuses stale edits and rolls back edits that fail JavaScript syntax validation.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        expectedHash: { type: "string" },
        operation: { type: "string", enum: ["replace", "insert_before", "insert_after", "append"] },
        oldText: { type: "string" },
        newText: { type: "string" },
        count: { type: "number" }
      },
      required: ["path", "expectedHash", "newText"]
    }
  },

  write_file: {
    name: "write_file",
    description: "Create or replace a UTF-8 text file inside the workspace.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        content: { type: "string" }
      },
      required: ["path", "content"]
    }
  },

  inspect_project: {
    name: "inspect_project",
    description: "Build a compact structural map of the workspace, package metadata, source-file count, imports, and exported symbols.",
    inputSchema: { type: "object", properties: { refresh: { type: "boolean" } } }
  },

  search_files: {
    name: "search_files",
    description: "Search the project index for relevant file paths and symbols before reading files.",
    inputSchema: {
      type: "object",
      properties: { query: { type: "string" }, limit: { type: "number" }, refresh: { type: "boolean" } },
      required: ["query"]
    }
  },

  find_symbol: {
    name: "find_symbol",
    description: "Find exported JavaScript/TypeScript symbols by name without reading unrelated files.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string" }, limit: { type: "number" }, refresh: { type: "boolean" } },
      required: ["name"]
    }
  }
,

  find_references: {
    name: "find_references",
    description: "Find declarations, imports, and source-code references to a JavaScript/TypeScript symbol.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string" }, path: { type: "string" }, limit: { type: "number" }, refresh: { type: "boolean" } },
      required: ["name"]
    }
  },

  find_file_references: {
    name: "find_file_references",
    description: "Find workspace files that import a specific project file.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" }, limit: { type: "number" }, refresh: { type: "boolean" } },
      required: ["path"]
    }
  },

  dependency_graph: {
    name: "dependency_graph",
    description: "Build a lightweight project dependency graph from resolved local imports.",
    inputSchema: { type: "object", properties: { refresh: { type: "boolean" } } }
  },

  analyze_impact: {
    name: "analyze_impact",
    description: "Analyze which workspace files may be affected if a project file changes, using reverse local-import dependencies.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" }, depth: { type: "number" }, refresh: { type: "boolean" } },
      required: ["path"]
    }
  },


  inspect_code: {
    name: "inspect_code",
    description: "Parse a JavaScript/TypeScript source file with an AST and return semantic symbols/imports without returning the full file.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" }, limit: { type: "number" }, refresh: { type: "boolean" } },
      required: ["path"]
    }
  },

  find_semantic_references: {
    name: "find_semantic_references",
    description: "Find AST identifier references to a JavaScript/TypeScript symbol with exact line and column information.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string" }, path: { type: "string" }, limit: { type: "number" }, refresh: { type: "boolean" } },
      required: ["name"]
    }
  },


  resolve_symbol: {
    name: "resolve_symbol",
    description: "Resolve a symbol in a specific JavaScript/TypeScript file to its local declaration or imported target.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string" }, path: { type: "string" }, refresh: { type: "boolean" } },
      required: ["name", "path"]
    }
  },

  call_graph: {
    name: "call_graph",
    description: "Inspect function call edges and resolve local or imported callees when possible.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" }, symbol: { type: "string" }, limit: { type: "number" }, refresh: { type: "boolean" } }
    }
  },

  plan_change: {
    name: "plan_change",
    description: "Build a read-only change plan using project search, references, dependency impact, symbol bindings, call graph, and current Git changes before editing.",
    inputSchema: {
      type: "object",
      properties: {
        task: { type: "string" },
        paths: { type: "array", items: { type: "string" } },
        symbols: { type: "array", items: { type: "string" } },
        depth: { type: "number" },
        refresh: { type: "boolean" }
      },
      required: ["task"]
    }
  },

  plan_verification: {
    name: "plan_verification",
    description: "Build a read-only verification plan from changed files, package scripts, and JavaScript syntax requirements. Does not execute commands.",
    inputSchema: {
      type: "object",
      properties: {
        paths: { type: "array", items: { type: "string" } },
        includeGit: { type: "boolean" }
      }
    }
  },

  execute_verification: {
    name: "execute_verification",
    description: "Execute only checks generated by the current verification planner. Commands are regenerated server-side and passed through the terminal safety policy; arbitrary commands are not accepted.",
    inputSchema: {
      type: "object",
      properties: {
        paths: { type: "array", items: { type: "string" } },
        includeGit: { type: "boolean" },
        checkIds: { type: "array", items: { type: "string" } },
        stopOnFailure: { type: "boolean" }
      }
    }
  },

  plan_refactoring: {
    name: "plan_refactoring",
    description: "Build a read-only refactoring plan using symbol/reference evidence and affected files before editing.",
    inputSchema: {
      type: "object",
      properties: {
        task: { type: "string" },
        path: { type: "string" },
        symbol: { type: "string" },
        newName: { type: "string" },
        refresh: { type: "boolean" }
      },
      required: ["task"]
    }
  },

  diagnose_verification_failure: {
    name: "diagnose_verification_failure",
    description: "Classify actual verification failures and identify relevant files/next diagnostic actions without editing or executing commands.",
    inputSchema: {
      type: "object",
      properties: {
        verification: { type: "object" },
        failures: { type: "array", items: { type: "object" } }
      }
    }
  },

  analyze_tests: {
    name: "analyze_tests",
    description: "Analyze likely tests for changed source files and available project test/check scripts without executing them.",
    inputSchema: {
      type: "object",
      properties: {
        paths: { type: "array", items: { type: "string" } },
        includeGit: { type: "boolean" },
        refresh: { type: "boolean" }
      }
    }
  },

  analyze_schemas: {
    name: "analyze_schemas",
    description: "Analyze observable TypeScript interfaces/types, runtime validation schemas, and JSON schemas without executing the application.",
    inputSchema: { type: "object", properties: { paths: { type: "array", items: { type: "string" } }, limit: { type: "number" } } }
  },

  analyze_frameworks: {
    name: "analyze_frameworks",
    description: "Detect observable framework usage, configuration files, and common project conventions without executing the application.",
    inputSchema: { type: "object", properties: { paths: { type: "array", items: { type: "string" } }, limit: { type: "number" } } }
  },

  review_change_set: {
    name: "review_change_set",
    description: "Review the current Git change set using changed files, untracked files, dependency impact, API/schema/framework evidence, and static risk signals before commit.",
    inputSchema: {
      type: "object",
      properties: {
        paths: { type: "array", items: { type: "string" } },
        includeGit: { type: "boolean" },
        depth: { type: "number" },
        limit: { type: "number" }
      }
    }
  },

  plan_migration: {
    name: "plan_migration",
    description: "Build a read-only migration plan using dependency, framework, API contract, schema, and source evidence before editing.",
    inputSchema: {
      type: "object",
      properties: {
        task: { type: "string" },
        paths: { type: "array", items: { type: "string" } },
        packages: { type: "array", items: { type: "string" } },
        limit: { type: "number" }
      },
      required: ["task"]
    }
  },

  analyze_contracts: {
    name: "analyze_contracts",
    description: "Analyze observable API routes, module exports, and imports without executing the application. Use this before changes that may alter an API or module contract.",
    inputSchema: {
      type: "object",
      properties: {
        paths: { type: "array", items: { type: "string" } },
        limit: { type: "number" }
      }
    }
  },

  search_code: {
    name: "search_code",
    description: "Search source-code contents and return matching file paths, line numbers, and short snippets without returning whole files.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string" },
        limit: { type: "number" },
        refresh: { type: "boolean" },
        caseSensitive: { type: "boolean" },
        regex: { type: "boolean" }
      },
      required: ["query"]
    }
  }
};

export async function runWorkspaceTool(name, input) {
  switch (name) {
    case "list_files":
      return listWorkspaceFiles();

    case "read_file":
      return readWorkspaceFile(input.path);

    case "write_file":
      return writeWorkspaceFile(input.path, input.content);

    case "edit_file":
      return safeEditFile(input);

    case "inspect_project":
      return inspectProject({ refresh: Boolean(input.refresh) });

    case "search_files":
      return searchWorkspace(input.query, { limit: input.limit, refresh: Boolean(input.refresh) });

    case "find_symbol":
      return findSymbol(input.name, { limit: input.limit, refresh: Boolean(input.refresh) });

    case "find_references":
      return findReferences(input.name, { path: input.path, limit: input.limit, refresh: Boolean(input.refresh) });

    case "find_file_references":
      return findReferencesToFile(input.path, { limit: input.limit, refresh: Boolean(input.refresh) });

    case "dependency_graph":
      return getDependencyGraph({ refresh: Boolean(input.refresh) });

    case "analyze_impact":
      return analyzeImpact(input.path, { depth: input.depth, refresh: Boolean(input.refresh) });

    case "inspect_code":
      return inspectCodeSemantics(input.path, { limit: input.limit, refresh: Boolean(input.refresh) });

    case "find_semantic_references":
      return findSemanticReferences(input.name, { path: input.path, limit: input.limit, refresh: Boolean(input.refresh) });

    case "resolve_symbol":
      return resolveSymbolBinding(input.name, { sourcePath: input.path, refresh: Boolean(input.refresh) });

    case "call_graph":
      return getCallGraph({ path: input.path, symbol: input.symbol, limit: input.limit, refresh: Boolean(input.refresh) });

    case "plan_change":
      return planChange({ task: input.task, paths: input.paths, symbols: input.symbols, depth: input.depth, refresh: Boolean(input.refresh) });

    case "plan_verification":
      return planVerification({ paths: input.paths, includeGit: input.includeGit !== false });

    case "execute_verification":
      return executeVerification({
        paths: input.paths,
        includeGit: input.includeGit !== false,
        checkIds: input.checkIds,
        stopOnFailure: Boolean(input.stopOnFailure)
      });

    case "analyze_tests":
      return analyzeTestIntelligence({ paths: input.paths, includeGit: input.includeGit !== false, refresh: Boolean(input.refresh) });

    case "diagnose_verification_failure":
      return diagnoseVerificationFailure({ verification: input.verification, failures: input.failures });

    case "plan_refactoring":
      return planRefactoring({ task: input.task, path: input.path, symbol: input.symbol, newName: input.newName, refresh: Boolean(input.refresh) });

    case "analyze_contracts":
      return analyzeContracts({ paths: input.paths, limit: input.limit });

    case "analyze_schemas":
      return analyzeSchemas({ paths: input.paths, limit: input.limit });

    case "analyze_frameworks":
      return analyzeFrameworks({ paths: input.paths, limit: input.limit });

    case "plan_migration":
      return planMigration({ task: input.task, paths: input.paths, packages: input.packages, limit: input.limit });

    case "review_change_set":
      return reviewChangeSet({ paths: input.paths, includeGit: input.includeGit !== false, depth: input.depth, limit: input.limit });

    case "search_code":
      return searchCode(input.query, {
        limit: input.limit,
        refresh: Boolean(input.refresh),
        caseSensitive: Boolean(input.caseSensitive),
        regex: Boolean(input.regex)
      });

    default:
      throw new Error(`Workspace tool tidak dikenal: ${name}`);
  }
}
