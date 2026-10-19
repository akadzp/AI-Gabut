import { AgenticError } from "./errors.js";

const ACTIONS=new Set(["pause","resume","cancel"]);
const TERMINAL=new Set(["completed","cancelled"]);
const issue=(code,message,path)=>({code,message,path});

export function createMissionControlIntegrity({clock=()=>Date.now()}={}){
  function inspect(ownerId,mission){
    const issues=[];
    if(!mission||typeof mission!=="object") return {valid:false,issues:[issue("MISSION_REQUIRED","Mission wajib berupa object","mission")]};
    if(mission.ownerId!==ownerId) issues.push(issue("MISSION_OWNER_MISMATCH","Mission bukan milik owner","ownerId"));
    const history=Array.isArray(mission.controlHistory)?mission.controlHistory:[];
    const ids=new Set(),requests=new Set();
    history.forEach((entry,index)=>{
      if(!entry||typeof entry!=="object") return issues.push(issue("CONTROL_HISTORY_ENTRY_INVALID","Control history entry tidak valid",`controlHistory[${index}]`));
      if(!entry.controlId) issues.push(issue("CONTROL_ID_REQUIRED","Control entry wajib memiliki controlId",`controlHistory[${index}].controlId`));
      else if(ids.has(entry.controlId)) issues.push(issue("CONTROL_ID_DUPLICATE","controlId harus unik",`controlHistory[${index}].controlId`)); else ids.add(entry.controlId);
      if(!ACTIONS.has(entry.action)) issues.push(issue("CONTROL_ACTION_INVALID","Action control tidak valid",`controlHistory[${index}].action`));
      if(entry.requestId){if(requests.has(entry.requestId)) issues.push(issue("CONTROL_REQUEST_DUPLICATE","requestId harus unik dalam control history",`controlHistory[${index}].requestId`)); else requests.add(entry.requestId);}
      if(!entry.createdAt||!Number.isFinite(Date.parse(entry.createdAt))) issues.push(issue("CONTROL_CREATED_AT_INVALID","createdAt control tidak valid",`controlHistory[${index}].createdAt`));
      if(entry.fromStatus!==undefined&&typeof entry.fromStatus!=="string") issues.push(issue("CONTROL_FROM_STATUS_INVALID","fromStatus control tidak valid",`controlHistory[${index}].fromStatus`));
      if(entry.toStatus!==undefined&&typeof entry.toStatus!=="string") issues.push(issue("CONTROL_TO_STATUS_INVALID","toStatus control tidak valid",`controlHistory[${index}].toStatus`));
      if(entry.fromStatus!==undefined&&entry.toStatus!==undefined){
        const expected=entry.action==="pause"?"paused":entry.action==="resume"?"running":entry.action==="cancel"?"cancelled":null;
        if(expected&&entry.toStatus!==expected) issues.push(issue("CONTROL_TRANSITION_TARGET_MISMATCH","toStatus tidak cocok dengan action control",`controlHistory[${index}].toStatus`));
        if(entry.fromStatus===entry.toStatus) issues.push(issue("CONTROL_TRANSITION_NOOP","Control transition tidak boleh memiliki fromStatus dan toStatus yang sama",`controlHistory[${index}]`));
      }
      if(entry.baseVersion!==undefined&&entry.baseVersion!==null&&(!Number.isInteger(entry.baseVersion)||entry.baseVersion<0)) issues.push(issue("CONTROL_BASE_VERSION_INVALID","baseVersion control tidak valid",`controlHistory[${index}].baseVersion`));
    });
    if(mission.controlId){
      const current=history.find(x=>x?.controlId===mission.controlId);
      if(!current) issues.push(issue("CONTROL_CURRENT_MISSING","controlId aktif tidak ditemukan dalam history","controlId"));
      else {
        if(mission.controlReason!==current.reason) issues.push(issue("CONTROL_REASON_MISMATCH","controlReason tidak cocok dengan control history","controlReason"));
        if((mission.controlRequestId||null)!==(current.requestId||null)) issues.push(issue("CONTROL_REQUEST_MISMATCH","controlRequestId tidak cocok dengan control history","controlRequestId"));
        if(mission.status==="paused"&&current.action!=="pause") issues.push(issue("CONTROL_PAUSE_MISMATCH","Mission paused harus memiliki control pause aktif","status"));
        if(mission.status==="cancelled"&&current.action!=="cancel") issues.push(issue("CONTROL_CANCEL_MISMATCH","Mission cancelled harus memiliki control cancel aktif","status"));
        if(mission.status==="running"&&current.action!=="resume"&&current.action!=="pause") issues.push(issue("CONTROL_RUNNING_MISMATCH","Mission running dengan controlId harus berasal dari pause/resume transition","status"));
      }
    }
    if(mission.controlEvidencePending){
      const pending=mission.controlEvidencePending;
      if(!pending.controlId) issues.push(issue("CONTROL_PENDING_ID_REQUIRED","Pending evidence wajib memiliki controlId","controlEvidencePending.controlId"));
      if(mission.controlId&&pending.controlId!==mission.controlId) issues.push(issue("CONTROL_PENDING_MISMATCH","Pending evidence tidak cocok dengan controlId","controlEvidencePending.controlId"));
      if(pending.action&&!ACTIONS.has(pending.action)) issues.push(issue("CONTROL_PENDING_ACTION_INVALID","Pending evidence action tidak valid","controlEvidencePending.action"));
      if(pending.requestId&&mission.controlRequestId&&pending.requestId!==mission.controlRequestId) issues.push(issue("CONTROL_PENDING_REQUEST_MISMATCH","Pending evidence requestId tidak cocok","controlEvidencePending.requestId"));
    }
    if(mission.controlEvidenceError&&!mission.controlEvidencePending) issues.push(issue("CONTROL_EVIDENCE_ERROR_ORPHANED","controlEvidenceError membutuhkan pending evidence","controlEvidenceError"));
    if(TERMINAL.has(mission.status)&&mission.controlEvidencePending&&mission.status==="completed") issues.push(issue("CONTROL_PENDING_ON_COMPLETED","Mission completed tidak boleh memiliki pending control evidence","controlEvidencePending"));
    return {valid:issues.length===0,issues};
  }

  function repair(ownerId,mission){
    const result=inspect(ownerId,mission); if(result.valid) return {changed:false,mission,issues:[],remainingIssues:[]};
    const next={...mission};
    const raw=Array.isArray(next.controlHistory)?next.controlHistory:[];
    const seenIds=new Set(),seenRequests=new Set(),history=[];
    for(const entry of raw){
      if(!entry||typeof entry!=="object"||!entry.controlId||!ACTIONS.has(entry.action)||seenIds.has(entry.controlId)) continue;
      if(entry.requestId&&seenRequests.has(entry.requestId)) continue;
      if(!entry.createdAt||!Number.isFinite(Date.parse(entry.createdAt))) continue;
      seenIds.add(entry.controlId); if(entry.requestId) seenRequests.add(entry.requestId); history.push({...entry});
    }
    next.controlHistory=history.slice(-50);
    if(next.controlId){
      const current=next.controlHistory.find(x=>x.controlId===next.controlId);
      if(!current){delete next.controlId;delete next.controlReason;delete next.controlRequestId;}
      else {next.controlReason=current.reason;next.controlRequestId=current.requestId||null;}
    }
    if(next.controlEvidencePending){
      const pending=next.controlEvidencePending;
      const current=next.controlHistory.find(x=>x.controlId===pending.controlId);
      if(!current){delete next.controlEvidencePending;delete next.controlEvidenceError;}
      else next.controlEvidencePending={...current};
    }
    if(next.controlEvidenceError&&!next.controlEvidencePending) delete next.controlEvidenceError;
    next.integrity={...(next.integrity||{}),controlLastRepairAt:new Date(clock()).toISOString(),controlRepairIssues:result.issues};
    const after=inspect(ownerId,next);
    return {changed:true,mission:next,issues:result.issues,remainingIssues:after.issues};
  }

  function assertValid(ownerId,mission){const result=inspect(ownerId,mission);if(!result.valid) throw new AgenticError("MISSION_CONTROL_INTEGRITY_INVALID","Mission control state tidak konsisten",409,{issues:result.issues});return mission;}
  return Object.freeze({inspect,repair,assertValid});
}
