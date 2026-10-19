import assert from "node:assert/strict";
import test from "node:test";
import { createExternalFeedbackService } from "../../apps/agentic/backend/external-feedback.js";

function fixture(){
  const map=new Map(); const refs=[];
  const work={
    async raw(){return{id:"work-1",state:"failed",context:{repository:{owner:"acme",name:"repo",defaultBranch:"main"}}}},
    async attachReference(...args){refs.push(args);}
  };
  const store={
    async putExternalFeedback(u,v){map.set(`${u}:${v.id}`,{...v,_storage:{version:1}})},
    async getExternalFeedback(u,id){return map.get(`${u}:${id}`)||null},
    async listExternalFeedback(u){return [...map.values()].filter(x=>x.ownerId===u)}
  };
  const github={
    async workflowRuns(){return[{id:11,name:"CI",status:"completed",conclusion:"failure",branch:"main",headSha:"abc",htmlUrl:"https://github.com/acme/repo/actions/runs/11"}]},
    async workflowJobs(){return[{id:22,name:"test",status:"completed",conclusion:"failure"}]},
    async jobLogs(){return{text:"AssertionError: expected 1 to equal 2"}}
  };
  const repair={async repair(_u,_w,o){assert.equal(o.externalFeedbackId,"feedback-1");return{repair:{status:"repaired",iterations:1},work:{id:"work-1"},execution:{id:"exec-1"}}}};
  return{work,store,github,repair,refs};
}

test("external feedback normalizes failure and keeps evidence",async()=>{const f=fixture();const svc=createExternalFeedbackService(f);const x=await svc.ingest("u","work-1",{id:"feedback-1",provider:"github",source:"github-actions",conclusion:"failure",failures:["test failed"],logs:"AssertionError"});assert.equal(x.status,"failed");assert.equal(x.failures[0],"test failed");assert.equal(f.refs[0][2],"feedback-1");});
test("GitHub CI feedback discovers run/jobs/log evidence",async()=>{const f=fixture();const svc=createExternalFeedbackService(f);const x=await svc.ingestGitHub("u","work-1",{connectionId:"gh"});assert.equal(x.externalId,11);assert.match(x.logs,/AssertionError/);});
test("failed external feedback can trigger bounded repair",async()=>{const f=fixture();const svc=createExternalFeedbackService(f);await svc.ingest("u","work-1",{id:"feedback-1",conclusion:"failure"});const x=await svc.triggerRepair("u","feedback-1");assert.equal(x.repair.status,"repaired");});
