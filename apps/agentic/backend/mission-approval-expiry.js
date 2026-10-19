import { AgenticError } from "./errors.js";
import { createId } from "./ids.js";

const nowIso=()=>new Date().toISOString();

export function createMissionApprovalExpiryService({store,realtime=null,observability=null,clock=()=>Date.now()}={}){
  if(!store?.getMission||!store?.putMission||!store?.getMissionApproval||!store?.putMissionApproval) throw new AgenticError("MISSION_APPROVAL_STORE_REQUIRED","Mission approval expiry membutuhkan mission persistence");
  const publish=async(owner,type,payload)=>{if(!realtime?.publish)return;await realtime.publish(owner,{id:createId("activity"),type,...payload,createdAt:nowIso()});};

  async function expire(owner,missionId,reason="Approval kedaluwarsa"){
    const mission=await store.getMission(owner,missionId);
    if(!mission) throw new AgenticError("MISSION_NOT_FOUND","Mission tidak ditemukan",404);
    if(mission.status!=="waiting_approval"||!mission.approval) throw new AgenticError("MISSION_APPROVAL_NOT_PENDING","Mission tidak sedang menunggu approval",409);
    const expiresAt=Date.parse(mission.approval.expiresAt||"");
    if(!Number.isFinite(expiresAt)||expiresAt>clock()) throw new AgenticError("MISSION_APPROVAL_NOT_EXPIRED","Approval belum kedaluwarsa",409);
    const index=Number(mission.currentStageIndex);
    const stage=mission.stages?.[index];
    if(!stage||stage.state!=="waiting_approval") throw new AgenticError("MISSION_APPROVAL_STAGE_INVALID","Stage approval tidak valid",409);
    const approvalId=mission.approval.id||createId("mission-approval");
    const decidedAt=nowIso();
    const approval={id:approvalId,ownerId:owner,missionId,stageId:stage.id,stageIndex:index,status:"expired",reason:String(reason||"Approval kedaluwarsa").trim().slice(0,1000),requestedAt:mission.approval.requestedAt||mission.updatedAt,expiresAt:mission.approval.expiresAt,decidedAt};
    const existing=await store.getMissionApproval(owner,approvalId);
    if(!existing) await store.putMissionApproval(owner,approval,{overwrite:false});
    const next={...mission,status:"failed",approval:null,stages:mission.stages.map((s,i)=>i===index?{...s,state:"failed",approvalId,approvalStatus:"expired",finishedAt:decidedAt}:s),history:[...(mission.history||[]),{stageId:stage.id,stageIndex:index,status:"approval_expired",approvalId,reason:approval.reason,decidedAt}],updatedAt:decidedAt};
    const saved=await store.putMission(owner,next,{expectedVersion:mission._storage?.version});
    await publish(owner,"mission.approval.expired",{missionId,stageId:stage.id,stageIndex:index,approvalId});
    if(observability?.event) await observability.event(owner,missionId,"approval_resolved",{stageId:stage.id,stageIndex:index,approvalId,status:"expired",reason:approval.reason,dedupeKey:`approval-resolved:${approvalId}:expired`});
    return {mission:saved,approval};
  }

  async function expireDue(owner){
    const missions=await store.listMissions?.(owner)||[];
    const out=[];
    for(const mission of missions){
      if(mission?.status!=="waiting_approval"||!mission.approval?.expiresAt) continue;
      if(Date.parse(mission.approval.expiresAt)>clock()) continue;
      try{out.push(await expire(owner,mission.id));}catch(error){
        if(error?.code!=="MISSION_APPROVAL_NOT_EXPIRED") throw error;
      }
    }
    return out;
  }
  return Object.freeze({expire,expireDue});
}
