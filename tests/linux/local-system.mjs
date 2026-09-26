import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const root = await fs.mkdtemp(path.join(os.tmpdir(), "ai-gabut-linux-"));
process.env.AI_WORKSPACE_ROOT = root;

try {
  const {
    getEnvironmentSnapshot,
    getSystemInfo,
    getResourceSnapshot,
    getCurrentProcessInfo,
    isProcessAlive,
    statWorkspacePath,
    listWorkspaceDirectory,
    detectPackageManagers,
    getPackageCapabilities,
    getServiceManager,
    getFilesystemCapabilities
  } = await import("../../core/linux/index.js");

  await fs.writeFile(path.join(root, "sample.txt"), "hello", "utf8");
  await fs.mkdir(path.join(root, "src"));

  const environment = getEnvironmentSnapshot({ environment: { SAFE: "1", API_TOKEN: "secret", NODE_ENV: "test" } });
  assert.equal(Object.hasOwn(environment.values, "API_TOKEN"), false);
  assert.equal(environment.platform, process.platform);

  const system = getSystemInfo();
  assert.equal(system.platform, process.platform);
  assert.ok(system.cpus >= 1);

  const resources = getResourceSnapshot();
  assert.ok(resources.memory.totalBytes > 0);
  assert.equal(resources.process.pid, process.pid);

  const current = getCurrentProcessInfo();
  assert.equal(current.pid, process.pid);
  assert.equal(isProcessAlive(process.pid), true);
  assert.equal(isProcessAlive(99999999), false);

  assert.deepEqual((await statWorkspacePath("sample.txt")).type, "file");
  assert.equal((await statWorkspacePath("missing.txt")), null);
  assert.deepEqual((await listWorkspaceDirectory(".")).map(item => item.name), ["sample.txt", "src"]);

  await fs.writeFile(path.join(root, "package.json"), JSON.stringify({ name: "test-workspace", version: "1.0.0" }), "utf8");
  assert.ok(Array.isArray(await detectPackageManagers({ relativePath: "." })));
  assert.deepEqual(await (await import("../../core/linux/package/index.js")).readPackageManifest({ relativePath: "package.json" }), { name: "test-workspace", version: "1.0.0" });
  assert.equal(getPackageCapabilities().mutation, false);
  assert.equal(getFilesystemCapabilities().readOnly, true);
  assert.ok(["systemd-or-init", "launchd", "windows-services", "unknown"].includes(getServiceManager()));

  await assert.rejects(
    statWorkspacePath("../outside"),
    /Path traversal|Sandbox/
  );
  await assert.rejects(
    listWorkspaceDirectory(".env"),
    /Sensitive filesystem path/
  );

  console.log("Local system capability contract: PASS");
} finally {
  await fs.rm(root, { recursive: true, force: true });
}
