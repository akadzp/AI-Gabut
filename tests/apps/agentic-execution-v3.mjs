import assert from "node:assert/strict";
import test from "node:test";
process.env.AGENTIC_CREDENTIAL_KEY="test-only-agentic-key-that-is-long-enough";

function memoryStorage() {
  const scopes = new Map();
  return { records(namespace) { const map = scopes.get(namespace) || new Map(); scopes.set(namespace, map); return {
    async get(key){return map.get(key)||null;}, async put(key,value,options={}){if(!options.overwrite&&map.has(key))throw new Error("duplicate");const previous=map.get(key);const version=(previous?._storage?.version||0)+1;const next={...value,_storage:{version,etag:String(version)}};map.set(key,next);return next;},
    async update(key,value,options={}){const previous=map.get(key);if(!previous)throw new Error("missing");return this.put(key,value,{...options,overwrite:true});}, async delete(key){map.delete(key);return true;}, async exists(key){return map.has(key);}, async list(){return [...map.keys()];}
  };}};
}

const {createAgenticApplication}=await import("../../apps/agentic/backend/application.js");

async function seededApp(agentRunner){return createAgenticApplication({storage:memoryStorage(),agentRunner});}

test("execution records are owned and statuses preserve bounded engine outcomes",async()=>{
  const app=await seededApp(async()=>({text:"Execution dihentikan secara bounded: autonomy",autonomy:{status:"stopped"},plan:[]}));
  const a=await app.auth.register({email:"a@example.com",password:"password-a-123"});
  const b=await app.auth.register({email:"b@example.com",password:"password-b-123"});
  const result=await app.chat(a.id,{prompt:"stop me"});
  assert.equal(result.execution.status,"stopped");
  assert.equal((await app.listExecutions(a.id)).length,1);
  assert.equal((await app.listExecutions(b.id)).length,0);
  assert.equal(await app.getExecution(b.id,result.execution.id).catch(e=>e.code),"EXECUTION_NOT_FOUND");
});

test("approval lifecycle is explicit and resumes the same execution",async()=>{
  let calls=0;
  const app=await seededApp(async(args)=>{
    calls++;
    if(!args.approvalToken)return {text:"blocked",tool:{steps:[{name:"git_commit",input:{message:"approved change"},result:{ok:false,requiresApproval:true,error:"Human approval required"}}]}};
    return {text:"commit completed",plan:[],execution:{id:args.executionId,status:"completed"}};
  });
  const u=await app.auth.register({email:"approval@example.com",password:"password-a-123"});
  const pending=await app.chat(u.id,{prompt:"commit the change"});
  assert.equal(pending.approvalRequired,true);
  assert.equal(pending.execution.status,"waiting_approval");
  const resumed=await app.approveExecution(u.id,pending.execution.id);
  assert.equal(resumed.execution.status,"completed");
  assert.equal(calls,2);
});

test("cancellation is user-owned and visible to an active runner",async()=>{
  let signalResolve;
  const signal=new Promise(resolve=>{signalResolve=resolve;});
  const app=await seededApp(async({onActivity})=>{await onActivity({action:"working",status:"running",label:"working"});await signal;await onActivity({action:"working",status:"completed",label:"done"});return {text:"done"};});
  const u=await app.auth.register({email:"cancel@example.com",password:"password-a-123"});
  const p=app.chat(u.id,{prompt:"long work"});
  while((await app.listExecutions(u.id)).length===0)await new Promise(r=>setTimeout(r,1));
  const id=(await app.listExecutions(u.id))[0].id;
  const cancelled=await app.cancelExecution(u.id,id);
  assert.equal(cancelled.status,"cancelled");
  signalResolve();
  const result=await p;
  assert.equal(result.execution.status,"cancelled");
});
