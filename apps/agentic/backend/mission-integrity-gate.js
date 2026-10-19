import { AgenticError } from "./errors.js";

export function createMissionIntegrityGate({store,integrity,realtime=null,clock=()=>Date.now()}={}){
  if(!store?.getMission||!store?.putMission) throw new AgenticError("MISSION_STORE_REQUIRED","Mission integrity gate membutuhkan mission persistence");
  if(!integrity?.inspect||!integrity?.repair) throw new AgenticError("MISSION_INTEGRITY_REQUIRED","Mission integrity gate membutuhkan integrity service");

  const publish=async(owner,type,payload)=>{
    if(!realtime?.publish) return;
    await realtime.publish(owner,{id:`mission-integrity-${Date.now().toString(36)}-${Math.random().toString(36).slice(2,8)}`,type,...payload,createdAt:new Date(clock()).toISOString()});
  };

  async function ensure(ownerId,mission,{repair=true}={}){
    const inspected=integrity.inspect(ownerId,mission);
    if(inspected.valid) return {mission,changed:false,repaired:false,issues:[]};
    if(!repair) throw new AgenticError("MISSION_INTEGRITY_INVALID","Mission state tidak konsisten",409,{issues:inspected.issues});

    const result=integrity.repair(ownerId,mission);
    if(result.remainingIssues?.length) throw new AgenticError("MISSION_INTEGRITY_UNREPAIRABLE","Mission state tidak dapat diperbaiki secara bounded",409,{issues:result.issues,remainingIssues:result.remainingIssues});
    const saved=await store.putMission(ownerId,result.mission,{expectedVersion:mission._storage?.version});
    await publish(ownerId,"mission.integrity.repaired",{missionId:saved.id,issues:result.issues});
    return {mission:saved,changed:true,repaired:true,issues:result.issues};
  }

  async function validate(ownerId,mission){
    const result=integrity.inspect(ownerId,mission);
    if(!result.valid) throw new AgenticError("MISSION_INTEGRITY_INVALID","Mission state tidak konsisten",409,{issues:result.issues});
    return result;
  }

  return Object.freeze({ensure,validate});
}
