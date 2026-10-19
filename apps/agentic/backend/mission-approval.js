import { AgenticError } from "./errors.js";
import { createId } from "./ids.js";

const nowIso=()=>new Date().toISOString();

export function createMissionApprovalService({store,journalService=null,realtime=null,observability=null,clock=()=>Date.now()}={}){
  if(!store?.getMission||!store?.putMission||!store?.putMissionApproval) throw new AgenticError("MISSION_APPROVAL_STORE_REQUIRED","Mission approval membutuhkan mission persistence");
  const publish=async(owner,type,payload)=>{if(!realtime?.publish)return;await realtime.publish(owner,{id:createId("activity"),type,...payload,createdAt:nowIso()});};

  async function get(owner,id){
    const a=await store.getMissionApproval(owner,id);
    if(!a) throw new AgenticError("MISSION_APPROVAL_NOT_FOUND","Approval mission tidak ditemukan",404);
    return a;
  }
  async function list(owner){ return store.listMissionApprovals?store.listMissionApprovals(owner):[]; }

  async function decide(owner,missionId,decision,reason=""){
    const mission=await store.getMission(owner,missionId);
    if(!mission) throw new AgenticError("MISSION_NOT_FOUND","Mission tidak ditemukan",404);
    if(mission.status!=="waiting_approval"||!mission.approval) throw new AgenticError("MISSION_APPROVAL_NOT_PENDING","Mission tidak sedang menunggu approval",409);
    const index=Number(mission.currentStageIndex);
    const stage=mission.stages?.[index];
    if(!stage||stage.state!=="waiting_approval") throw new AgenticError("MISSION_APPROVAL_STAGE_INVALID","Stage approval tidak valid",409);
    const approvalId=mission.approval.id||createId("mission-approval");
    const status=decision==="approve"?"approved":"rejected";
    const approval={id:approvalId,ownerId:owner,missionId,stageId:stage.id,stageIndex:index,status,reason:String(reason||"").trim().slice(0,1000),requestedAt:mission.approval.requestedAt||mission.updatedAt,decidedAt:nowIso()};
    await store.putMissionApproval(owner,approval,{overwrite:false});
    if(decision==="approve"){
      if(journalService?.reopen) await journalService.reopen(owner,missionId,stage.id,"approval_granted");
      const next={...mission,status:"scheduled",approval:null,nextRunAt:new Date(clock()).toISOString(),stages:mission.stages.map((s,i)=>i===index?{...s,state:"pending",approvalId,status:null}:s),history:[...(mission.history||[]),{stageId:stage.id,stageIndex:index,status:"approval_granted",approvalId,reason:approval.reason,decidedAt:approval.decidedAt}],updatedAt:approval.decidedAt};
      const saved=await store.putMission(owner,next,{expectedVersion:mission._storage?.version});
      await publish(owner,"mission.approval.decided",{missionId,stageId:stage.id,stageIndex:index,approvalId,status:"approved"});
      if(observability?.event) await observability.event(owner,missionId,"approval_resolved",{stageId:stage.id,stageIndex:index,approvalId,status:"approved",reason:approval.reason,dedupeKey:`approval-resolved:${approvalId}:approved`});
      return {mission:saved,approval};
    }
    const next={...mission,status:"failed",approval:null,stages:mission.stages.map((s,i)=>i===index?{...s,state:"failed",approvalId,finishedAt:approval.decidedAt}:s),history:[...(mission.history||[]),{stageId:stage.id,stageIndex:index,status:"approval_rejected",approvalId,reason:approval.reason,decidedAt:approval.decidedAt}],updatedAt:approval.decidedAt};
    const saved=await store.putMission(owner,next,{expectedVersion:mission._storage?.version});
    await publish(owner,"mission.approval.decided",{missionId,stageId:stage.id,stageIndex:index,approvalId,status:"rejected"});
    if(observability?.event) await observability.event(owner,missionId,"approval_resolved",{stageId:stage.id,stageIndex:index,approvalId,status:"rejected",reason:approval.reason,dedupeKey:`approval-resolved:${approvalId}:rejected`});
    return {mission:saved,approval};
  }

  async function approve(owner,missionId,reason="") { return decide(owner,missionId,"approve",reason); }
  async function reject(owner,missionId,reason="") { return decide(owner,missionId,"reject",reason); }
  return Object.freeze({get,list,approve,reject});
}
