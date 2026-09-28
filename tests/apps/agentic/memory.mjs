import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createStorage } from "../../../core/storage/index.js";
import { createAgenticStore } from "../../../apps/agentic/backend/store.js";
import { createMemoryService } from "../../../apps/agentic/backend/memory.js";

const root=await fs.mkdtemp(path.join(os.tmpdir(),"ai-gabut-memory-"));
try {
  const store=createAgenticStore({storage:createStorage({root})});
  const memory=createMemoryService({store});

  await memory.create("user-a",{type:"preference",content:"User prefers TypeScript for new projects",tags:["typescript","project"]});
  await memory.create("user-a",{type:"decision",content:"Agentic workspace uses a monorepo layout",tags:["workspace"]});
  await memory.create("user-b",{type:"preference",content:"User prefers Python for scripts",tags:["python"]});

  const result=await memory.search("user-a","TypeScript project");
  assert.equal(result.length,1);
  assert.match(result[0].content,/TypeScript/);
  assert.equal((await memory.search("user-a","Python")).length,0);

  const context=await memory.buildContext("user-a","monorepo workspace",{limit:1});
  assert.equal(context.memories.length,1);
  assert.match(context.memories[0].content,/monorepo/);

  await assert.rejects(
    memory.create("user-a",{type:"credential",content:"secret token"}),
    /Credential material/
  );
  await assert.rejects(
    memory.create("user-a",{type:"fact",content:"Bearer abcdefghijklmnop"}),
    /Credential-like/
  );

  const all=await memory.list("user-a");
  assert.equal(all.length,2);
  assert.equal((await memory.remove("user-a",all[0].id)),true);
  assert.equal((await memory.list("user-a")).length,1);

  console.log("Agentic memory/context: PASS");
} finally {
  await fs.rm(root,{recursive:true,force:true});
}
