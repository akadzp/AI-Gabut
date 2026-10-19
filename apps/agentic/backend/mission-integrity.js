import { AgenticError } from "./errors.js";

const TERMINAL=new Set(["completed","failed","cancelled"]);
const ACTIVE=new Set(["scheduled","running","waiting_approval","paused"]);
const STAGE_STATES=new Set(["pending","running","waiting_approval","failed","completed"]);

const issue=(code,message,path)=>({code,message,path});

export function createMissionIntegrity({clock=()=>Date.now()}={}){
  const nowIso=()=>new Date(clock()).toISOString();

  function inspect(ownerId,mission){
    const issues=[];
    if(!mission||typeof mission!=="object") return {valid:false,issues:[issue("MISSION_REQUIRED","Mission wajib berupa object","mission")]};
    if(mission.ownerId!==ownerId) issues.push(issue("MISSION_OWNER_MISMATCH","Mission bukan milik owner","ownerId"));
    if(!mission.id) issues.push(issue("MISSION_ID_REQUIRED","Mission wajib memiliki id","id"));
    if(!Array.isArray(mission.stages)||mission.stages.length===0) issues.push(issue("MISSION_STAGES_REQUIRED","Mission membutuhkan minimal satu stage","stages"));
    const stages=Array.isArray(mission.stages)?mission.stages:[];
    const ids=new Set();
    stages.forEach((stage,index)=>{
      if(!stage?.id) issues.push(issue("MISSION_STAGE_ID_REQUIRED","Stage wajib memiliki id",`stages[${index}].id`));
      else if(ids.has(stage.id)) issues.push(issue("MISSION_STAGE_ID_DUPLICATE","Stage id harus unik",`stages[${index}].id`));
      else ids.add(stage.id);
      if(stage?.state&&!STAGE_STATES.has(stage.state)) issues.push(issue("MISSION_STAGE_STATE_INVALID","State stage tidak valid",`stages[${index}].state`));
    });

    const index=Number(mission.currentStageIndex);
    if(!Number.isInteger(index)||index<0) issues.push(issue("MISSION_STAGE_INDEX_INVALID","currentStageIndex harus integer >= 0","currentStageIndex"));
    const boundedIndex=Number.isInteger(index)&&index>=0?index:0;
    if(stages.length&&mission.status!=="completed"&&boundedIndex>=stages.length) issues.push(issue("MISSION_STAGE_INDEX_OUT_OF_RANGE","currentStageIndex melewati stage terakhir","currentStageIndex"));
    if(mission.status==="completed"&&stages.length&&boundedIndex<stages.length) issues.push(issue("MISSION_COMPLETED_INDEX_INVALID","Mission completed harus menunjuk setelah stage terakhir","currentStageIndex"));
    if(![...TERMINAL,...ACTIVE].includes(mission.status)) issues.push(issue("MISSION_STATUS_INVALID","Status mission tidak valid","status"));
    if(mission.status==="running"&&stages[boundedIndex]?.state!=="running") issues.push(issue("MISSION_RUNNING_STAGE_MISMATCH","Mission running harus memiliki current stage running",`stages[${boundedIndex}].state`));
    if(mission.status==="waiting_approval"&&stages[boundedIndex]?.state!=="waiting_approval") issues.push(issue("MISSION_APPROVAL_STAGE_MISMATCH","Mission waiting_approval harus memiliki current stage waiting_approval",`stages[${boundedIndex}].state`));
    if(mission.status==="failed"&&stages[boundedIndex]?.state!=="failed") issues.push(issue("MISSION_FAILED_STAGE_MISMATCH","Mission failed harus memiliki current stage failed",`stages[${boundedIndex}].state`));
    if(mission.status==="scheduled"&&(!mission.nextRunAt||!Number.isFinite(Date.parse(mission.nextRunAt)))) issues.push(issue("MISSION_NEXT_RUN_INVALID","Mission scheduled wajib memiliki nextRunAt valid","nextRunAt"));
    return {valid:issues.length===0,issues};
  }

  function assertValid(ownerId,mission){
    const result=inspect(ownerId,mission);
    if(!result.valid) throw new AgenticError("MISSION_INTEGRITY_INVALID","Mission state tidak konsisten",409,{issues:result.issues});
    return mission;
  }

  function repair(ownerId,mission){
    const result=inspect(ownerId,mission);
    if(result.valid) return {changed:false,mission,issues:[]};
    const next={...mission};
    const stages=Array.isArray(next.stages)?next.stages.map(s=>({...s})):[];
    const ids=new Set();
    const normalized=[];
    for(const stage of stages){
      if(!stage?.id||ids.has(stage.id)) continue;
      ids.add(stage.id);normalized.push(stage);
    }
    next.stages=normalized;
    if(!next.ownerId) next.ownerId=ownerId;
    if(!Number.isInteger(next.currentStageIndex)||next.currentStageIndex<0) next.currentStageIndex=0;
    if(next.stages.length===0){next.status="failed";next.currentStageIndex=0;}
    else if(next.status==="completed") next.currentStageIndex=next.stages.length;
    else if(next.currentStageIndex>=next.stages.length) next.currentStageIndex=next.stages.length-1;
    if(next.status==="running"&&next.stages[next.currentStageIndex]) next.stages[next.currentStageIndex].state="running";
    if(next.status==="waiting_approval"&&next.stages[next.currentStageIndex]) next.stages[next.currentStageIndex].state="waiting_approval";
    if(next.status==="failed"&&next.stages[next.currentStageIndex]) next.stages[next.currentStageIndex].state="failed";
    if(next.status==="scheduled"&&(!next.nextRunAt||!Number.isFinite(Date.parse(next.nextRunAt)))) next.nextRunAt=nowIso();
    next.integrity={...(next.integrity||{}),lastRepairAt:nowIso(),repairIssues:result.issues};
    const after=inspect(ownerId,next);
    return {changed:true,mission:next,issues:result.issues,remainingIssues:after.issues};
  }

  return Object.freeze({inspect,assertValid,repair});
}
