import assert from "node:assert/strict";
import test from "node:test";
import { createWorkspaceService } from "../../apps/agentic/backend/workspaces.js";

function makeStore() {
  const data = new Map();
  return {
    async putWorkspace(ownerId, value) { data.set(`${ownerId}--${value.id}`, {...value, ownerId}); return data.get(`${ownerId}--${value.id}`); },
    async getWorkspace(ownerId, id) { return data.get(`${ownerId}--${id}`) || null; },
    async listWorkspaces(ownerId) { return [...data.values()].filter(x=>x.ownerId===ownerId); }
  };
}
function makeConnections() {
  const data = new Map();
  return {
    seed(ownerId, c) { data.set(`${ownerId}--${c.id}`, {...c, ownerId}); },
    async raw(ownerId,id) { const c=data.get(`${ownerId}--${id}`); if(!c) throw Object.assign(new Error("not found"),{code:"CONNECTION_NOT_FOUND"}); return c; }
  };
}
test("workspace binds owned connection, repository and branch", async()=>{
  const store=makeStore(), connections=makeConnections();
  connections.seed("a",{id:"conn-1",provider:"github",status:"active"});
  const service=createWorkspaceService({store,connections});
  service.registerProvider("github",{repositoryContext:async({owner,name,branch})=>({repository:{fullName:`${owner}/${name}`},branch:{name,sha:"abc"},capabilities:["repository","branch"]})});
  const w=await service.create("a",{name:"AI-Gabut",provider:"github",connectionId:"conn-1",repository:{owner:"akadzp",name:"AI-Gabut"},branch:"main"});
  assert.equal(w.repository.fullName,"akadzp/AI-Gabut");
  assert.equal(w.branch,"main");
  assert.equal(w.context.branch.sha,"abc");
  assert.equal(w.ownerId,"a");
});
test("cross-user workspace access is denied", async()=>{
  const store=makeStore(), connections=makeConnections();
  connections.seed("a",{id:"conn-1",provider:"github",status:"active"});
  const service=createWorkspaceService({store,connections});
  const w=await service.create("a",{provider:"github",connectionId:"conn-1",repository:{owner:"o",name:"r"},branch:"main"});
  await assert.rejects(()=>service.get("b",w.id),e=>e.code==="WORKSPACE_NOT_FOUND");
});
test("workspace context refresh and current file remain explicit", async()=>{
  const store=makeStore(), connections=makeConnections();
  connections.seed("a",{id:"conn-1",provider:"github",status:"active"});
  let n=0;
  const service=createWorkspaceService({store,connections});
  service.registerProvider("github",{repositoryContext:async()=>({version:++n,capabilities:["repository","branch","tree","file","search"]})});
  const w=await service.create("a",{provider:"github",connectionId:"conn-1",repository:{owner:"o",name:"r"},branch:"main"});
  const refreshed=await service.refresh("a",w.id);
  const selected=await service.setCurrentFile("a",w.id,"src/index.js");
  assert.equal(refreshed.context.version,2);
  assert.equal(selected.currentFile,"src/index.js");
});
