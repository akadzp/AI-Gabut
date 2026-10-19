import { createId } from "./ids.js";

const DEFAULT_STALE_AFTER_MS=60*60*1000;
const terminalStatuses=new Set(["completed","failed","waiting_approval","cancelled"]);

export function createMissionExecutionJournal({store,clock=()=>Date.now(),staleAfterMs=DEFAULT_STALE_AFTER_MS}={}){
  if(!store?.getOwned||!store?.putOwned) throw new TypeError("Mission execution journal membutuhkan owned store");
  const threshold=Math.max(60*1000,Number(staleAfterMs)||DEFAULT_STALE_AFTER_MS);
  const key=(missionId,stageId)=>`mission-execution:${missionId}:${stageId}`;
  const nowIso=()=>new Date(clock()).toISOString();

  async function get(ownerId,missionId,stageId){
    return store.getOwned("mission-execution-journal",ownerId,key(missionId,stageId));
  }

  async function begin(ownerId,missionId,stageId,executionId){
    const now=clock();
    const existing=await get(ownerId,missionId,stageId);
    if(existing?.status==="completed") return {state:"completed",entry:existing};
    if(existing?.status==="waiting_approval") return {state:"waiting_approval",entry:existing};
    if(existing?.status==="failed") return {state:"failed",entry:existing};
    if(existing?.status==="running"&&existing.executionId!==executionId){
      const started=Date.parse(existing.startedAt||"");
      if(Number.isFinite(started)&&now-started<threshold){
        throw Object.assign(new Error("mission stage execution is already journaled as running"),{code:"MISSION_EXECUTION_CONFLICT",entry:existing});
      }
    }
    const entry={id:existing?.id||createId("mission-journal"),ownerId,missionId,stageId,executionId,status:"running",startedAt:nowIso(),updatedAt:nowIso()};
    await store.putOwned("mission-execution-journal",ownerId,key(missionId,stageId),entry,{expectedVersion:existing?._storage?.version});
    return {state:"started",entry};
  }

  async function reopen(ownerId,missionId,stageId,reason="approval_granted"){
    const existing=await get(ownerId,missionId,stageId);
    if(!existing) throw Object.assign(new Error("mission journal entry not found"),{code:"MISSION_JOURNAL_NOT_FOUND"});
    if(existing.status!=="waiting_approval") throw Object.assign(new Error("mission journal is not waiting for approval"),{code:"MISSION_JOURNAL_NOT_WAITING"});
    const entry={...existing,status:"ready",reopenedAt:nowIso(),updatedAt:nowIso(),reopenReason:String(reason||"").slice(0,500)};
    return store.putOwned("mission-execution-journal",ownerId,key(missionId,stageId),entry,{expectedVersion:existing._storage?.version});
  }

  async function finalize(ownerId,missionId,stageId,executionId,status,result=null){
    if(!terminalStatuses.has(status)) throw Object.assign(new Error("invalid mission journal terminal status"),{code:"MISSION_JOURNAL_STATUS_INVALID"});
    const existing=await get(ownerId,missionId,stageId);
    if(existing?.executionId&&existing.executionId!==executionId&&existing.status!=="running"){
      throw Object.assign(new Error("mission journal is owned by another execution"),{code:"MISSION_JOURNAL_NOT_OWNER"});
    }
    const entry={...(existing||{}),id:existing?.id||createId("mission-journal"),ownerId,missionId,stageId,executionId,status,result,resultSummary:result?{status:result.status||null}:null,finishedAt:nowIso(),updatedAt:nowIso()};
    return store.putOwned("mission-execution-journal",ownerId,key(missionId,stageId),entry,{expectedVersion:existing?._storage?.version});
  }

  return Object.freeze({get,begin,finalize,reopen,staleAfterMs:threshold});
}
