#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectRecoverySloEvidenceExportBundle } from "../apps/agentic/backend/recovery-slo-export-restore.js";

const MAX_INPUT_BYTES = 25 * 1024 * 1024;
const usage = "Usage: node scripts/verify-recovery-slo-export.mjs --bundle <file.json> [--public-key <public.pem>] [--expected-owner <ownerId>] [--require-signature]";

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (item === "--require-signature") { options.requireSignature = true; continue; }
    if (["--bundle", "--public-key", "--expected-owner"].includes(item)) {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw Object.assign(new Error(`Missing value for ${item}`), { exitCode: 64 });
      options[item.slice(2).replaceAll("-", "")] = value;
      index += 1;
      continue;
    }
    if (item === "--help" || item === "-h") { options.help = true; continue; }
    throw Object.assign(new Error(`Unknown option: ${item}`), { exitCode: 64 });
  }
  if (!options.help && !options.bundle) throw Object.assign(new Error("--bundle is required"), { exitCode: 64 });
  return options;
}

async function main() {
  let options;
  try { options = parseArgs(process.argv.slice(2)); }
  catch (error) { process.stderr.write(`${error.message}\n${usage}\n`); process.exitCode = error.exitCode || 64; return; }
  if (options.help) { process.stdout.write(`${usage}\n`); return; }

  let bundle;
  let publicKey = null;
  try {
    const bundlePath = path.resolve(options.bundle);
    const stat = await fs.stat(bundlePath);
    if (!stat.isFile() || stat.size > MAX_INPUT_BYTES) throw Object.assign(new Error("Bundle must be a regular file no larger than 25 MiB"), { exitCode: 66 });
    bundle = JSON.parse(await fs.readFile(bundlePath, "utf8"));
    if (options.publickey) {
      const keyPath = path.resolve(options.publickey);
      const keyStat = await fs.stat(keyPath);
      if (!keyStat.isFile() || keyStat.size > 64 * 1024) throw Object.assign(new Error("Public key file must be a regular file no larger than 64 KiB"), { exitCode: 66 });
      publicKey = await fs.readFile(keyPath, "utf8");
    }
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = error.exitCode || 66;
    return;
  }

  const result = inspectRecoverySloEvidenceExportBundle(bundle, {
    publicKey,
    expectedOwnerId: options.expectedowner,
    requireSignature: options.requireSignature === true
  });
  const output = {
    tool: "agentic-ai-v4-recovery-slo-export-verifier",
    toolVersion: 1,
    sourceFile: path.basename(path.resolve(options.bundle)),
    ...result,
    notes: [
      "Verification is read-only and does not import or restore records.",
      "A valid signature proves key possession, not that the supplied public key is trusted; establish key trust independently."
    ]
  };
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  if (!result.valid) process.exitCode = 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
