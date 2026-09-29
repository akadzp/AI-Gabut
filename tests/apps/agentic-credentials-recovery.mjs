import assert from "node:assert/strict";
import test from "node:test";
process.env.AGENTIC_CREDENTIAL_KEY="test-only-agentic-key-that-is-long-enough";

import { createAgenticStore } from "../../apps/agentic/backend/store.js";
import { createCredentialService } from "../../apps/agentic/backend/credential-store.js";
import { createRecoveryService } from "../../apps/agentic/backend/recovery.js";

function memoryStorage(){
  const scopes=new Map();
  return{records(ns){const m=scopes.get(ns)||new Map();scopes.set(ns,m);return{
    async get(k){return m.get(k)||null},
    async put(k,v,o={}){const p=m.get(k);if(!o.overwrite&&p)throw Error("duplicate");if(o.expectedVersion!=null&&p?._storage?.version!==o.expectedVersion)throw Error("conflict");const n={...v,_storage:{version:(p?._storage?.version||0)+1}};m.set(k,n);return n},
    async update(k,v,o={}){return this.put(k,v,{...o,overwrite:true})},
    async delete(k){m.delete(k);return true},
    async exists(k){return m.has(k)},
    async list(){return [...m.keys()]}
  }}}
}

test("credential state is separate, encrypted, owned and revocable",async()=>{
  const store=createAgenticStore({storage:memoryStorage()});
  const svc=createCredentialService({store});
  const ref=await svc.put("u1",{connectionId:"c1",provider:"github",secret:"ghp_super_secret_value"});
  const raw=await store.getConnectionCredential("u1",ref.id);
  assert.equal(raw.ownerId,"u1");
  assert.equal(raw.ciphertext.includes("ghp_super_secret_value"),false);
  assert.equal(await svc.get("u1",ref.id),"ghp_super_secret_value");
  assert.rejects(()=>svc.get("u2",ref.id));
  assert.equal(await svc.revoke("u1",ref.id),true);
  assert.rejects(()=>svc.get("u1",ref.id));
});

test("restart recovery converts in-flight executions into explicit recoverable state",async()=>{
  const store=createAgenticStore({storage:memoryStorage()});
  await store.createUser({id:"u1",email:"u@example.com"});
  await store.putExecution("u1",{id:"e1",status:"running",sessionId:"s1"});
  await store.putExecution("u1",{id:"e2",status:"completed",sessionId:"s1"});
  const recovery=createRecoveryService({store});
  const found=await recovery.scan("u1");
  assert.equal(found.length,1);
  assert.equal(found[0].execution.status,"interrupted");
  const loaded=await recovery.get("u1","e1");
  assert.equal(loaded.recoverable,true);
  const resumed=await recovery.markResuming("u1","e1");
  assert.equal(resumed.status,"running");
  assert.equal(resumed.recoverable,false);
});
