import { AgenticError } from "./errors.js";

export function createMissionObservabilityIntegrityGate({observability,realtime=null,clock=()=>Date.now()}={}){
  if(!observability?.inspect||!observability?.repair) throw new AgenticError("MISSION_OBSERVABILITY_REQUIRED","Mission observability integrity gate membutuhkan observability service");

  const publish=async(ownerId,type,payload)=>{
    if(!realtime?.publish) return;
    await realtime.publish(ownerId,{id:`mission-observability-integrity-${Date.now().toString(36)}-${Math.random().toString(36).slice(2,8)}`,type,...payload,createdAt:new Date(clock()).toISOString()});
  };

  async function reconcile(ownerId,missionId){
    const report=await observability.inspect(ownerId,missionId);
    if(report.healthy) return {healthy:true,repaired:false,report};
    try{
      const result=await observability.repair(ownerId,missionId);
      const after=await observability.inspect(ownerId,missionId);
      if(result.repaired) await publish(ownerId,"mission.observability.repaired",{missionId,issues:report.issues,eventCount:after.eventCount});
      return {healthy:after.healthy,repaired:result.repaired,report,after,result};
    }catch(error){
      await publish(ownerId,"mission.observability.repair_failed",{missionId,issues:report.issues,error:{code:error.code||"OBSERVABILITY_REPAIR_FAILED",message:error.message||String(error)}});
      return {healthy:false,repaired:false,report,error:{code:error.code||"OBSERVABILITY_REPAIR_FAILED",message:error.message||String(error)}};
    }
  }

  return Object.freeze({reconcile});
}
