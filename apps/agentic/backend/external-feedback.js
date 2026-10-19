import { AgenticError } from "./errors.js";
import { createId } from "./ids.js";

const now=()=>new Date().toISOString();
const text=(v,max=12000)=>String(v??"").slice(0,max);

function normalize(input={}) {
  const conclusion=String(input.conclusion||input.status||"").toLowerCase();
  const status=conclusion==="success"||conclusion==="passed"||conclusion==="neutral"||conclusion==="skipped"
    ? "passed"
    : conclusion==="queued"||conclusion==="in_progress"||conclusion==="pending"
      ? "running" : "failed";
  return {
    status,
    provider:String(input.provider||"github"),
    source:String(input.source||"ci"),
    externalId:input.externalId||input.runId||input.jobId||null,
    name:text(input.name||"External verification",300),
    conclusion:conclusion||null,
    url:input.url||null,
    sha:input.sha||null,
    branch:input.branch||null,
    failures:Array.isArray(input.failures)?input.failures.slice(0,20).map(x=>text(x,2000)):[],
    logs:text(input.logs,200000),
    summary:text(input.summary,5000),
    receivedAt:now()
  };
}

export function createExternalFeedbackService({store,work,github:githubClient,repair=null,realtime=null}={}) {
  if(!store?.putExternalFeedback||!store?.getExternalFeedback||!store?.listExternalFeedback) throw new TypeError("External feedback membutuhkan feedback store contract");
  if(!work?.raw||!work?.attachReference) throw new TypeError("External feedback membutuhkan Work contract");

  async function raw(ownerId,id){const x=await store.getExternalFeedback(ownerId,id);if(!x)throw new AgenticError("EXTERNAL_FEEDBACK_NOT_FOUND","External feedback tidak ditemukan",404);return x;}

  async function persist(ownerId,workId,input={}) {
    await work.raw(ownerId,workId);
    const feedback=normalize(input);
    const record={id:input.id||createId("feedback"),ownerId,workId,...feedback,repair:null,createdAt:now(),updatedAt:now()};
    await store.putExternalFeedback(ownerId,record,{overwrite:false});
    await work.attachReference(ownerId,workId,record.id,"external-feedback");
    return record;
  }

  async function ingest(ownerId,workId,input={}) {
    const record=await persist(ownerId,workId,input);
    if(realtime) await realtime.publish(ownerId,{id:createId("activity"),type:"work",action:"external_feedback",status:record.status,label:`External feedback · ${record.status}`,meta:{workId,feedbackId:record.id,provider:record.provider,source:record.source}});
    return record;
  }

  async function ingestGitHub(ownerId,workId,input={}) {
    const workRecord=await work.raw(ownerId,workId);
    const repository=input.repository||workRecord.context?.repository;
    if(!repository?.owner||!repository?.name) throw new AgenticError("GITHUB_REPOSITORY_REQUIRED","Repository GitHub wajib ditentukan",409);
    if(!input.connectionId) throw new AgenticError("GITHUB_CONNECTION_REQUIRED","GitHub connection wajib ditentukan",409);
    const ref=input.ref||workRecord.context?.branch||repository.defaultBranch||"main";
    const runs=await githubClient.workflowRuns(ownerId,input.connectionId,repository.owner,repository.name,{branch:ref,headSha:input.sha||null});
    const selected=input.runId?runs.find(r=>String(r.id)===String(input.runId)):runs[0];
    if(!selected) throw new AgenticError("CI_RUN_NOT_FOUND","CI workflow run tidak ditemukan",404);
    const jobs=await githubClient.workflowJobs(ownerId,input.connectionId,repository.owner,repository.name,selected.id);
    const failed=jobs.filter(j=>j.conclusion==="failure"||j.status==="failure");
    const failures=failed.map(j=>`${j.name}: ${j.conclusion||j.status}`);
    const logs=[];
    for(const job of failed.slice(0,5)) { try { const l=await githubClient.jobLogs(ownerId,input.connectionId,repository.owner,repository.name,job.id); if(l?.text) logs.push(l.text); } catch {} }
    return ingest(ownerId,workId,{provider:"github",source:"github-actions",externalId:selected.id,name:selected.name||"GitHub Actions",conclusion:selected.conclusion||selected.status,url:selected.htmlUrl||selected.url,sha:selected.headSha,branch:selected.branch,failures,logs:logs.join("\n"),summary:failed.length?`${failed.length} CI job(s) failed`:`CI run ${selected.conclusion||selected.status}`});
  }

  async function triggerRepair(ownerId,feedbackId,options={}) {
    const record=await raw(ownerId,feedbackId);
    if(record.status!=="failed") throw new AgenticError("EXTERNAL_FEEDBACK_NOT_FAILED","Repair hanya dapat dipicu dari feedback failure",409);
    if(!repair?.repair) throw new AgenticError("REPAIR_UNAVAILABLE","Repair service tidak tersedia",503);
    const failure={type:"external_feedback_failure",source:record.source,retryable:true,reason:record.summary||record.failures.join("; ")||"External verification failed",evidenceId:record.id};
    const result=await repair.repair(ownerId,record.workId,{...options,externalFailure:failure,externalFeedbackId:record.id});
    record.repair={triggered:true,at:now(),result:{status:result.repair?.status||null,iterations:result.repair?.iterations||0}};
    record.updatedAt=now();
    await store.putExternalFeedback(ownerId,record,{overwrite:true,expectedVersion:record._storage?.version});
    return {feedback:record,...result};
  }

  return Object.freeze({get:raw,list:async u=>(await store.listExternalFeedback(u)).sort((a,b)=>String(b.updatedAt).localeCompare(String(a.updatedAt))),ingest,ingestGitHub,triggerRepair});
}
