import assert from "node:assert/strict";
import test from "node:test";

import { createAgenticStore } from "../../apps/agentic/backend/store.js";
import { createRecoveryService } from "../../apps/agentic/backend/recovery.js";

function memoryStorage(){
  const scopes=new Map();
  return {
    records(ns){const m=scopes.get(ns)||new Map();scopes.set(ns,m);return {
      async get(k){return m.get(k)||null},
      async put(k,v,o={}){const p=m.get(k);if(!o.overwrite&&p)throw Error("duplicate");if(o.expectedVersion!=null&&p?._storage?.version!==o.expectedVersion)throw Error("conflict");const n={...v,_storage:{version:(p?._storage?.version||0)+1}};m.set(k,n);return n},
      async update(k,v,o={}){return this.put(k,v,{...o,overwrite:true})},
      async delete(k){m.delete(k);return true},
      async exists(k){return m.has(k)},
      async list(){return [...m.keys()]}
    }}
  };
}

test("work recovery marks interrupted execution as paused with checkpoint and visible recovery state",async()=>{
  const store=createAgenticStore({storage:memoryStorage()});
  await store.createUser({id:"u1",email:"u@example.com"});
  const old=new Date(Date.now()-60*60*1000).toISOString();
  await store.putWork("u1",{id:"w1",ownerId:"u1",objective:"resume me",state:"running",result:null,createdAt:old,updatedAt:old});
  await store.putExecution("u1",{id:"e1",ownerId:"u1",workId:"w1",status:"running",checkpoint:{stepId:"step-2"},updatedAt:old,startedAt:old});

  const recovery=createRecoveryService({store});
  const found=await recovery.scan("u1",{staleAfterMs:1000});
  assert.equal(found.length,1);
  assert.equal(found[0].execution.status,"paused");
  assert.equal(found[0].execution.recovery.recoverable,true);
  assert.deepEqual(found[0].execution.recovery.lastCheckpoint,{stepId:"step-2"});

  const work=await store.getWork("u1","w1");
  assert.equal(work.state,"paused");
  assert.equal(work.result.recovery.status,"interrupted");
  assert.equal(work.result.recovery.executionId,"e1");

  const visible=await recovery.list("u1");
  assert.equal(visible.length,1);
  assert.equal(visible[0].workId,"w1");

  const second=await recovery.scan("u1",{staleAfterMs:1000});
  assert.equal(second.length,0);
});

test("recovery resume preparation is idempotence-aware and preserves checkpoint",async()=>{
  const store=createAgenticStore({storage:memoryStorage()});
  await store.createUser({id:"u1",email:"u@example.com"});
  await store.putWork("u1",{id:"w1",ownerId:"u1",objective:"resume",state:"paused",result:{recovery:{status:"interrupted",executionId:"e1"}},createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()});
  await store.putExecution("u1",{id:"e1",ownerId:"u1",workId:"w1",status:"paused",checkpoint:{stepId:"step-3"},recovery:{status:"interrupted",recoverable:true,resumeCount:0},updatedAt:new Date().toISOString()});

  const recovery=createRecoveryService({store});
  const prepared=await recovery.prepareResume("u1","e1");
  assert.equal(prepared.execution.recovery.resumeCount,1);
  assert.deepEqual(prepared.execution.recovery.lastCheckpoint,{stepId:"step-3"});
  const preparedAgain=await recovery.prepareResume("u1","e1");
  assert.equal(preparedAgain.execution.recovery.resumeCount,2);
});
