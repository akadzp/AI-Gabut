import { AgenticError } from "./errors.js";
import { createId } from "./ids.js";

const DEFAULT_CADENCE_MS=60*60*1000;
const MAX_STAGES=1000;
const ACTIVE=new Set(["scheduled"]);
const TERMINAL=new Set(["completed","failed","cancelled"]);
const nowIso=()=>new Date().toISOString();
const asTime=v=>{const n=Date.parse(v||"");return Number.isFinite(n)?n:null};

function normalizeStage(stage,index){
  if(typeof stage==="string") return {id:`stage-${index+1}`,title:stage,workId:null,state:"pending",attempts:0};
  const s=stage&&typeof stage==="object"?stage:{};
  return {id:String(s.id||`stage-${index+1}`),title:String(s.title||s.name||`Stage ${index+1}`).slice(0,200),workId:s.workId||null,state:"pending",attempts:0,...s};
}

export function createMissionScheduler({store,runWork,repairWork=null,realtime=null,observability=null,leaseService=null,journalService=null,integrityGate=null,observabilityIntegrityGate=null,approvalExpiryService=null,clock=()=>Date.now(),cadenceMs=DEFAULT_CADENCE_MS}={}){
  if(!store?.putMission||!store?.getMission||!store?.listMissions) throw new AgenticError("MISSION_STORE_REQUIRED","Mission scheduler membutuhkan mission persistence");
  if(typeof runWork!=="function") throw new AgenticError("MISSION_RUNNER_REQUIRED","Mission scheduler membutuhkan Work execution runner");
  const publish=async(owner,type,payload)=>{if(!realtime?.publish)return;await realtime.publish(owner,{id:createId("activity"),type,...payload,createdAt:nowIso()})};

  async function get(owner,id){const m=await store.getMission(owner,id);if(!m)throw new AgenticError("MISSION_NOT_FOUND","Mission tidak ditemukan",404);return m;}

  async function create(owner,input={}){
    const stages=(Array.isArray(input.stages)?input.stages:[]).slice(0,MAX_STAGES).map(normalizeStage);
    if(!stages.length) throw new AgenticError("MISSION_STAGES_REQUIRED","Mission membutuhkan minimal satu stage");
    const cadence=Math.max(60*1000,Number(input.cadenceMs)||cadenceMs);
    const startAt=input.startAt||new Date(clock()).toISOString();
    if(asTime(startAt)==null) throw new AgenticError("MISSION_START_INVALID","startAt mission tidak valid");
    const mission={id:createId("mission"),ownerId:owner,title:String(input.title||"Autonomous Mission").slice(0,200),objective:String(input.objective||"").slice(0,2000),status:"scheduled",cadenceMs:cadence,nextRunAt:startAt,currentStageIndex:0,stages,history:[],approval:null,createdAt:nowIso(),updatedAt:nowIso()};
    await store.putMission(owner,mission);return mission;
  }

  async function tick(owner,id,{at=clock()}={}){
    let mission=await get(owner,id);
    if(integrityGate){
      const integrity=await integrityGate.ensure(owner,mission,{repair:true});
      mission=integrity.mission;
    }
    if(TERMINAL.has(mission.status)) return {mission,executed:false,reason:"terminal"};
    const observabilityIntegrity=observabilityIntegrityGate?.reconcile?await observabilityIntegrityGate.reconcile(owner,id):null;
    if(mission.status==="waiting_approval") return {mission,executed:false,reason:"waiting_approval"};
    const due=asTime(mission.nextRunAt);
    if(due!=null&&due>at) return {mission,executed:false,reason:"not_due"};
    const index=Number(mission.currentStageIndex)||0;
    const stage=mission.stages[index];
    if(!stage){const completed={...mission,status:"completed",updatedAt:nowIso()};await store.putMission(owner,completed,{expectedVersion:mission._storage?.version});return {mission:completed,executed:false,reason:"completed",observabilityIntegrity};}
    const executionId=createId("mission-execution");
    let lease=null;
    if(leaseService){ lease=await leaseService.acquire(owner,id,executionId); }
    let journal=null;
    if(journalService){
      journal=await journalService.begin(owner,id,stage.id,executionId);
      if(journal.state==="completed"||journal.state==="waiting_approval"||journal.state==="failed") {
        const j=journal.entry;
        const recoveredStatus=j.status;
        const nextIndex=recoveredStatus==="completed"?index+1:index;
        const nextStatus=recoveredStatus==="completed"?(nextIndex>=mission.stages.length?"completed":"scheduled"):recoveredStatus;
        const finishedAt=j.finishedAt||nowIso();
        const reconciled={...mission,status:nextStatus,currentStageIndex:nextIndex,stages:mission.stages.map((s,i)=>i===index?{...s,state:recoveredStatus==="completed"?"completed":recoveredStatus,finishedAt,lastResult:j.result||null,reconciledFromJournal:true}:s),history:[...(mission.history||[]),{stageId:stage.id,stageIndex:index,startedAt:mission.updatedAt,finishedAt,status:recoveredStatus,result:j.result||null,reconciledFromJournal:true,executionId:j.executionId}],nextRunAt:nextStatus==="scheduled"?new Date(at+mission.cadenceMs).toISOString():mission.nextRunAt,updatedAt:finishedAt};
        let saved;
        try { saved=await store.putMission(owner,reconciled,{expectedVersion:mission._storage?.version}); }
        finally { if(leaseService&&lease){try{await leaseService.release(owner,id,executionId)}catch{}} }
        return {mission:saved,executed:false,reason:"journal_reconciled",stageIndex:index,observabilityIntegrity};
      }
    }
    const startedAt=nowIso();
    const running={...mission,status:"running",stages:mission.stages.map((s,i)=>i===index?{...s,state:"running",startedAt,attempts:(s.attempts||0)+1}:s),updatedAt:startedAt};
    const persistedRunning=await store.putMission(owner,running,{expectedVersion:mission._storage?.version});
    running._storage=persistedRunning?._storage||running._storage;
    if(observability?.event) await observability.event(owner,id,"stage_started",{stageId:stage.id,stageIndex:index,executionId,dedupeKey:`stage-started:${executionId}`});
    await publish(owner,"mission.stage.started",{missionId:id,stageId:stage.id,stageIndex:index});
    let result;
    try{result=await runWork(owner,stage.workId,stage);}
    catch(error){result={status:"failed",error:{code:error.code||"MISSION_STAGE_FAILED",message:error.message||String(error)}};}
    const status=result?.status||result?.work?.status||result?.execution?.status||"completed";
    const waiting=status==="waiting_approval"||result?.approval?.required===true;
    const failed=!waiting&&["failed","cancelled","stopped","max_turns"].includes(status);
    const finishedAt=nowIso();
    let nextStatus=waiting?"waiting_approval":failed?"failed":"scheduled";
    let nextIndex=index;
    if(!waiting&&!failed) nextIndex=index+1;
    if(nextIndex>=mission.stages.length&&!waiting&&!failed) nextStatus="completed";
    const historyEntry={stageId:stage.id,stageIndex:index,startedAt,finishedAt,status:waiting?"waiting_approval":failed?"failed":"completed",result:result||null};
    const updated={...running,approval:waiting?(result?.approval||{required:true}):null,status:nextStatus,currentStageIndex:nextIndex,stages:running.stages.map((s,i)=>i===index?{...s,state:waiting?"waiting_approval":failed?"failed":"completed",finishedAt,lastResult:result||null}:s),history:[...(running.history||[]),historyEntry],nextRunAt:nextStatus==="scheduled"?new Date(at+mission.cadenceMs).toISOString():mission.nextRunAt,updatedAt:finishedAt};
    if(failed&&repairWork){
      try{const repair=await repairWork(owner,stage.workId,{source:"mission",missionId:id,stageId:stage.id});updated.stages=updated.stages.map((s,i)=>i===index?{...s,repair}:s);updated.history.at(-1).repair=repair;}catch(error){updated.history.at(-1).repair={status:"failed",error:{code:error.code||"REPAIR_FAILED",message:error.message||String(error)}};}
    }
    let persisted=updated;
    if(journalService){
      const journalStatus=waiting?"waiting_approval":failed?"failed":"completed";
      await journalService.finalize(owner,id,stage.id,executionId,journalStatus,result||null);
    }
    try {
      persisted=await store.putMission(owner,updated,{expectedVersion:running._storage?.version});
    } finally {
      if(leaseService&&lease){
        try { await leaseService.release(owner,id,executionId); }
        catch(error){ persisted={...persisted,leaseReleaseError:{code:error.code||"LEASE_RELEASE_FAILED",message:error.message||String(error)}}; }
      }
    }
    if(observability?.event){
      const eventType=waiting?"approval_requested":failed?"stage_failed":"stage_completed";
      const dedupeKey=waiting?`approval-requested:${updated.approval?.id||stage.id}`:`stage-${failed?"failed":"completed"}:${executionId}`;
      await observability.event(owner,id,eventType,{stageId:stage.id,stageIndex:index,executionId,result:result||null,error:failed?result?.error||null:null,expiresAt:waiting?(updated.approval?.expiresAt||null):null,dedupeKey});
      if(persisted.status==="completed") await observability.event(owner,id,"mission_completed",{stageId:stage.id,stageIndex:index,executionId,dedupeKey:`mission-completed:${id}`});
    }
    await publish(owner,"mission.stage.finished",{missionId:id,stageId:stage.id,stageIndex:index,status:persisted.status,executionId});
    return {mission:persisted,executed:true,result,stageIndex:index,observabilityIntegrity};
  }

  async function runDue(owner,{at=clock()}={}){
    const expiredApprovals=approvalExpiryService?.expireDue?await approvalExpiryService.expireDue(owner):[];
    const missions=(await store.listMissions(owner)).filter(m=>ACTIVE.has(m.status)||m.status==="scheduled");
    const results=[];
    for(const m of missions){
      if(asTime(m.nextRunAt)==null||asTime(m.nextRunAt)>at) continue;
      results.push(await tick(owner,m.id,{at}));
    }
    results.expiredApprovals=expiredApprovals;
    return results;
  }

  return Object.freeze({create,get,tick,runDue,DEFAULT_CADENCE_MS});
}
