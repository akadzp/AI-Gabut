import assert from "node:assert/strict";
import test from "node:test";
import { createVerificationService } from "../../apps/agentic/backend/verification.js";

function makeStore() {
  const data = new Map(); const scope = n => data.get(n) || data.set(n, new Map()).get(n);
  const put = (n,u,v) => { const m=scope(n), k=`${u}--${v.id}`, old=m.get(k); const saved={...v,ownerId:u,_storage:{version:(old?._storage?.version||0)+1}}; m.set(k,saved); return saved; };
  const get = (n,u,id) => scope(n).get(`${u}--${id}`)||null; const list=(n,u)=>[...scope(n).values()].filter(x=>x.ownerId===u);
  return { putVerification:async(u,v)=>put("verification",u,v),getVerification:async(u,id)=>get("verification",u,id),listVerifications:async u=>list("verification",u),putWork:async(u,v)=>put("work",u,v),getWork:async(u,id)=>get("work",u,id) };
}
function runtime(runner){ const store=makeStore(); const refs=[]; const work={raw:async(u,id)=>{const x=await store.getWork(u,id);if(!x)throw new Error("missing");return x;},get:async(u,id)=>store.getWork(u,id),attachReference:async(_u,_id,_k,e)=>{refs.push(e);return true;},recordVerification:async(u,id,v)=>{const x=await store.getWork(u,id);const next={...x,result:{...(x.result||{}),verification:v},evidenceIds:[...(x.evidenceIds||[]),v.verificationId]};return store.putWork(u,next);}}; return {store,work,refs,service:createVerificationService({store,work,runner})}; }

test("verification normalizes pass/fail and retains stdout stderr evidence",async()=>{const {service,store,refs}=runtime(async(spec)=>({exitCode:0,signal:null,stdout:"ok\n",stderr:"",timedOut:false}));await store.putWork("u",{id:"w",state:"completed",context:{},evidenceIds:[]});const r=await service.verify("u","w",{command:["npm","test"],cwd:"/tmp"});assert.equal(r.verification.status,"passed");assert.equal(r.verification.stdout,"ok\n");assert.deepEqual(refs,[r.verification.id]);assert.equal((await service.list("u","w")).length,1);});

test("verification extracts failures and retries bounded attempts",async()=>{
  let n=0;
  const rt=runtime(async()=>{n++;return n===1?{exitCode:1,signal:null,stdout:"FAIL test\n",stderr:"AssertionError: expected 1\n",timedOut:false}:{exitCode:0,signal:null,stdout:"PASS test\n",stderr:"",timedOut:false};});
  await rt.store.putWork("u",{id:"w",state:"completed",context:{},evidenceIds:[]});
  const r=await rt.service.verify("u","w",{command:["npm","test"],cwd:"/tmp",maxAttempts:2});
  assert.equal(r.verification.status,"passed"); assert.equal(r.history.length,2); assert.ok(r.history[0].failures.some(x=>x.includes("AssertionError"))); assert.equal((await rt.service.list("u","w")).length,2);
});

test("verification records timeout and enforces explicit local cwd boundary",async()=>{const {service,store}=runtime(async()=>({exitCode:null,signal:"SIGTERM",stdout:"",stderr:"",timedOut:true}));await store.putWork("u",{id:"w",state:"failed",context:{},evidenceIds:[]});const r=await service.verify("u","w",{command:["npm","test"],cwd:"/tmp",maxAttempts:1});assert.equal(r.verification.status,"timed_out");const rt=runtime(async()=>({exitCode:0,signal:null,stdout:"",stderr:"",timedOut:false}));await rt.store.putWork("u",{id:"w",state:"completed",context:{},evidenceIds:[]});await assert.rejects(()=>rt.service.verify("u","w",{command:["npm","test"]}),e=>e.code==="VERIFICATION_CWD_REQUIRED");});
