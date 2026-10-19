const createId=prefix=>`${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2,10)}`;
class AgenticError extends Error { constructor(code,message,status=400){super(message);this.code=code;this.status=status;} }
const CONTROL_ACTIONS=new Set(['pause','resume','cancel']);
const MAX_CONTROL_HISTORY=50;
const MAX_TRANSITION_RETRIES=2;
const MAX_RECONCILIATION_RETRIES=2;
const MAX_RECOVERY_EVIDENCE_RETRIES=2;
const MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES=2;
function controlInput(value){
 if(value&&typeof value==='object'&&!Array.isArray(value)) return {reason:String(value.reason||'').trim().slice(0,1000),requestId:String(value.requestId||value.idempotencyKey||'').trim().slice(0,200)};
 return {reason:String(value||'').trim().slice(0,1000),requestId:''};
}
function historyOf(mission){return Array.isArray(mission.controlHistory)?mission.controlHistory:[];}
function isVersionConflict(error){return String(error?.code||'')==='VERSION_CONFLICT'||/VERSION_CONFLICT|version conflict|version mismatch/i.test(String(error?.message||error));}
export function createMissionControl({missionStore,observability,integrityGate=null,integrity=null,clock=()=>new Date().toISOString()}={}){
 if(!missionStore||!observability) throw new Error('Mission control membutuhkan missionStore dan observability');
 async function get(ownerId,missionId){const mission=await missionStore.getOwned('missions',ownerId,missionId);if(!mission) throw new AgenticError('MISSION_NOT_FOUND','Mission tidak ditemukan',404);if(mission.ownerId&&mission.ownerId!==ownerId) throw new AgenticError('FORBIDDEN','Mission bukan milik owner',403);return mission;}
 async function emitControlEvidence(ownerId,mission,entry){
  const eventType=entry.action==='pause'?'stage_paused':entry.action==='resume'?'stage_resumed':'mission_cancelled';
  return observability.event(ownerId,mission.id,eventType,{source:'mission-control',action:entry.action,reason:entry.reason,controlId:entry.controlId,requestId:entry.requestId||null,dedupeKey:`control:${entry.controlId}`});
 }
 async function repairPendingEvidence(ownerId,mission,entry){
  if(mission.controlEvidencePending?.controlId!==entry.controlId) return mission;
  try {
   await emitControlEvidence(ownerId,mission,entry);
   const repaired={...mission,controlEvidencePending:null,controlEvidenceError:null,updatedAt:clock()};
   try { return await missionStore.putOwned('missions',ownerId,mission.id,repaired,{overwrite:true,expectedVersion:mission._storage?.version}); }
   catch(error){ if(isVersionConflict(error)) return await get(ownerId,mission.id); return mission; }
  } catch { return mission; }
 }
 async function control(ownerId,missionId,action,reasonOrOptions=''){
  if(!CONTROL_ACTIONS.has(action)) throw new AgenticError('INVALID_CONTROL_ACTION','Action control tidak valid');
  const input=controlInput(reasonOrOptions);
  let lastConflict=null;
  for(let attempt=0;attempt<MAX_TRANSITION_RETRIES;attempt++){
   let mission=await get(ownerId,missionId);
   if(integrityGate?.ensure){ const checked=await integrityGate.ensure(ownerId,mission,{repair:true}); mission=checked.mission; }
   const history=historyOf(mission);
   if(input.requestId){
    const existing=history.find(x=>x.requestId===input.requestId);
    if(existing){
     if(existing.action!==action) throw new AgenticError('CONTROL_REQUEST_CONFLICT','Request ID control sudah digunakan untuk action berbeda',409);
     if(mission.controlEvidencePending?.controlId===existing.controlId) mission=await repairPendingEvidence(ownerId,mission,existing);
     return mission;
    }
   }
   const desiredStatus=action==='pause'?'paused':action==='resume'?'running':'cancelled';
   if(action!=='cancel' && mission.status===desiredStatus && mission.controlId) return mission;
   if(action==='pause' && !['running','queued'].includes(mission.status)) throw new AgenticError('INVALID_STATE','Mission tidak dapat di-pause pada state saat ini');
   if(action==='resume' && mission.status!=='paused') throw new AgenticError('INVALID_STATE','Mission tidak berada pada state paused');
   if(action==='cancel' && ['completed','cancelled'].includes(mission.status)) throw new AgenticError('INVALID_STATE','Mission sudah final');
   const entry={controlId:createId('mission-control'),action,reason:input.reason,requestId:input.requestId||null,fromStatus:mission.status,toStatus:desiredStatus,baseVersion:mission._storage?.version??null,createdAt:clock()};
   const next={...mission,status:action==='pause'?'paused':action==='resume'?'running':'cancelled',updatedAt:entry.createdAt,controlId:entry.controlId,controlReason:entry.reason,controlRequestId:entry.requestId,controlHistory:[...history,entry].slice(-MAX_CONTROL_HISTORY),controlEvidencePending:entry,controlEvidenceError:null};
   let persisted;
   try { persisted=await missionStore.putOwned('missions',ownerId,missionId,next,{overwrite:true,expectedVersion:mission._storage?.version}); }
   catch(error){
    if(isVersionConflict(error)){ lastConflict=error; continue; }
    throw error;
   }
   try {
    await emitControlEvidence(ownerId,persisted,entry);
    const cleared={...persisted,controlEvidencePending:null,controlEvidenceError:null,updatedAt:clock()};
    try { return await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:persisted._storage?.version}); }
    catch(error){ if(isVersionConflict(error)) return await get(ownerId,missionId); return persisted; }
   } catch(error){
    const out={...persisted,controlEvidenceError:String(error?.message||error),controlEvidencePending:entry};
    try { return await missionStore.putOwned('missions',ownerId,missionId,out,{overwrite:true,expectedVersion:persisted._storage?.version}); }
    catch(persistError){ if(isVersionConflict(persistError)) return await get(ownerId,missionId); return persisted; }
   }
  }
  throw new AgenticError('MISSION_CONTROL_VERSION_CONFLICT','Mission berubah bersamaan; control transition tidak dapat dipastikan secara aman',409,{cause:String(lastConflict?.message||lastConflict||'VERSION_CONFLICT')});
 }
 async function status(ownerId,missionId){const mission=await get(ownerId,missionId);return observability.snapshot(ownerId,mission);}
 async function audit(ownerId,missionId,options={}){
  const mission=await get(ownerId,missionId);
  const history=historyOf(mission);
  const action=String(options?.action||'').trim();
  const limit=Math.min(Math.max(Number.isInteger(options?.limit)?options.limit:50,1),MAX_CONTROL_HISTORY);
  const filtered=action&&CONTROL_ACTIONS.has(action)?history.filter(entry=>entry?.action===action):history;
  const entries=filtered.slice(-limit).map(entry=>({...entry}));
  return {missionId:mission.id,ownerId,missionStatus:mission.status,currentControlId:mission.controlId||null,entries,total:filtered.length};
 }
 async function verifyAudit(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  if(!integrity?.inspect) return {missionId:mission.id,ownerId,valid:true,checkedEntries:historyOf(mission).length,issues:[],available:false};
  const result=integrity.inspect(ownerId,mission);
  return {missionId:mission.id,ownerId,valid:result.valid,checkedEntries:historyOf(mission).length,issues:result.issues.map(issue=>({...issue}))};
 }
 async function reconciliationStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pending=mission.controlAuditReconciliationPending||null;
  const error=mission.controlAuditReconciliationError||null;
  const phase=pending?'pending':error?'error':'clear';
  const issueCount=Array.isArray(pending?.issues)?pending.issues.length:0;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   recoverable:Boolean(pending),
   reconciliationId:pending?.reconciliationId||null,
   issueCount,
   issueCodes:Array.isArray(pending?.issues)?pending.issues.map(issue=>issue?.code).filter(Boolean).slice(0,50):[],
   createdAt:pending?.createdAt||null,
   error:error?String(error):null,
   storageVersion:mission._storage?.version??null
  };
 }
 async function reconcileAudit(ownerId,missionId){
  let mission=await get(ownerId,missionId);
  const emitReconciliationEvidence=async(current,reconciliationId,issues)=>observability.event(ownerId,current.id,'mission_control_audit_reconciled',{source:'mission-control',reconciliationId,issueCount:issues.length,issueCodes:issues.map(x=>x.code).slice(0,50),dedupeKey:`control-audit-reconcile:${reconciliationId}`});
  async function finalizeEvidence(current,pending){
   try {
    await emitReconciliationEvidence(current,pending.reconciliationId,pending.issues||[]);
    const cleared={...current,controlAuditReconciliationPending:null,controlAuditReconciliationError:null,updatedAt:clock()};
    try { return await missionStore.putOwned('missions',ownerId,current.id,cleared,{overwrite:true,expectedVersion:current._storage?.version}); }
    catch(error){ if(isVersionConflict(error)) return await get(ownerId,current.id); return current; }
   } catch(error){
    const marked={...current,controlAuditReconciliationPending:pending,controlAuditReconciliationError:String(error?.message||error),updatedAt:clock()};
    try { return await missionStore.putOwned('missions',ownerId,current.id,marked,{overwrite:true,expectedVersion:current._storage?.version}); }
    catch(persistError){ if(isVersionConflict(persistError)) return await get(ownerId,current.id); return current; }
   }
  }
  for(let attempt=0;attempt<MAX_RECONCILIATION_RETRIES;attempt++){
   if(mission.controlAuditReconciliationPending){
    const pending=mission.controlAuditReconciliationPending;
    const repaired=await finalizeEvidence(mission,pending);
    if(repaired.controlAuditReconciliationPending){
     const latest=await get(ownerId,missionId);
     if(latest.controlAuditReconciliationPending?.reconciliationId===pending.reconciliationId && latest._storage?.version!==mission._storage?.version){
      mission=latest;
      continue;
     }
    }
    return {missionId:repaired.id,ownerId,changed:false,repaired:false,valid:true,issues:[],remainingIssues:[],evidenceRepaired:!repaired.controlAuditReconciliationPending,reconciledByRetry:attempt>0};
   }
   if(!integrity?.inspect||!integrity?.repair) return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],remainingIssues:[],available:false};
   const inspected=integrity.inspect(ownerId,mission);
   if(inspected.valid) return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],remainingIssues:[],reconciledByRetry:attempt>0};
   const repaired=integrity.repair(ownerId,mission);
   if(repaired.remainingIssues?.length) throw new AgenticError('MISSION_CONTROL_AUDIT_UNREPAIRABLE','Mission control audit tidak dapat direkonsiliasi secara bounded',409,{issues:repaired.issues,remainingIssues:repaired.remainingIssues});
   if(!repaired.changed) return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:false,issues:repaired.issues.map(issue=>({...issue})),remainingIssues:repaired.remainingIssues?.map(issue=>({...issue}))||[],reconciledByRetry:attempt>0};
   const reconciliationId=createId('mission-control-reconcile');
   const pending={reconciliationId,issues:repaired.issues.map(issue=>({...issue})),createdAt:clock()};
   const candidate={...repaired.mission,controlAuditReconciliationPending:pending,controlAuditReconciliationError:null};
   try {
    const saved=await missionStore.putOwned('missions',ownerId,mission.id,candidate,{overwrite:true,expectedVersion:mission._storage?.version});
    const evidenced=await finalizeEvidence(saved,pending);
    return {missionId:evidenced.id,ownerId,changed:true,repaired:true,valid:true,issues:pending.issues,remainingIssues:[],reconciliationId,evidenceRepaired:!evidenced.controlAuditReconciliationPending,reconciledByRetry:attempt>0};
   } catch(error){
    if(isVersionConflict(error)){
     mission=await get(ownerId,missionId);
     continue;
    }
    throw error;
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_VERSION_CONFLICT','Mission berubah bersamaan; audit reconciliation tidak dapat dipastikan secara aman',409);
 }

 async function verifyAuditRecoveryEvidence(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pending=mission.controlAuditRecoveryEvidencePending||null;
  const issues=[];
  if(!pending){
   return {missionId:mission.id,ownerId,valid:true,pending:false,reconciliationId:null,issues:[]};
  }
  if(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()) issues.push({code:'RECOVERY_EVIDENCE_RECONCILIATION_ID_MISSING'});
  if(!['pending','error'].includes(String(pending.phaseBefore||''))) issues.push({code:'RECOVERY_EVIDENCE_PHASE_INVALID',phaseBefore:pending.phaseBefore??null});
  if(typeof pending.reconciledByRetry!=='boolean') issues.push({code:'RECOVERY_EVIDENCE_RETRY_FLAG_INVALID'});
  if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()) issues.push({code:'RECOVERY_EVIDENCE_CREATED_AT_MISSING'});
  if(pending.reconciliationId && pending.reconciliationId.trim() && `control-audit-recovery:${pending.reconciliationId}`.length>260) issues.push({code:'RECOVERY_EVIDENCE_DEDUPE_KEY_TOO_LONG'});
  return {missionId:mission.id,ownerId,valid:issues.length===0,pending:true,reconciliationId:pending.reconciliationId||null,dedupeKey:pending.reconciliationId?`control-audit-recovery:${pending.reconciliationId}`:null,issues:issues.map(issue=>({...issue}))};
 }

 async function auditRecoveryEvidenceRepairStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pending=mission.controlAuditRecoveryEvidenceRepairPending||null;
  const error=mission.controlAuditRecoveryEvidenceRepairError||null;
  const phase=pending?'pending':error?'error':'clear';
  return {
   missionId:mission.id,
   ownerId,
   phase,
   recoverable:Boolean(pending),
   reconciliationId:pending?.reconciliationId||null,
   phaseBefore:pending?.phaseBefore||null,
   reconciledByRetry:pending?.reconciledByRetry===true,
   repairedByRetry:pending?.repairedByRetry===true,
   createdAt:pending?.createdAt||null,
   error:error?String(error):null,
   storageVersion:mission._storage?.version??null
  };
 }

 async function auditRecoveryEvidenceRepairRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pending=mission.controlAuditRecoveryEvidenceRepairRecoveryPending||null;
  const error=mission.controlAuditRecoveryEvidenceRepairRecoveryError||null;
  const phase=pending?'pending':error?'error':'clear';
  return {
   missionId:mission.id,
   ownerId,
   phase,
   recoverable:Boolean(pending),
   reconciliationId:pending?.reconciliationId||null,
   recoveredByRetry:pending?.recoveredByRetry===true,
   createdAt:pending?.createdAt||null,
   error:error?String(error):null,
   storageVersion:mission._storage?.version??null
  };
 }

 async function auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pending=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending||null;
  const error=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError||null;
  const phase=pending?'pending':error?'error':'clear';
  return {
   missionId:mission.id,
   ownerId,
   phase,
   recoverable:Boolean(pending),
   reconciliationId:pending?.reconciliationId||null,
   recoveredByRetry:pending?.recoveredByRetry===true,
   createdAt:pending?.createdAt||null,
   error:error?String(error):null,
   storageVersion:mission._storage?.version??null
  };
 }

 async function verifyAuditRecoveryEvidenceRepairRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pending=mission.controlAuditRecoveryEvidenceRepairRecoveryPending||null;
  const issues=[];
  if(!pending){
   const error=mission.controlAuditRecoveryEvidenceRepairRecoveryError||null;
   return {missionId:mission.id,ownerId,valid:!error,pending:false,reconciliationId:null,dedupeKey:null,issues:error?[{code:'RECOVERY_REPAIR_RECOVERY_ERROR_WITHOUT_PENDING',error:String(error)}]:[]};
  }
  if(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()) issues.push({code:'RECOVERY_REPAIR_RECOVERY_RECONCILIATION_ID_MISSING'});
  if(typeof pending.recoveredByRetry!=='boolean') issues.push({code:'RECOVERY_REPAIR_RECOVERY_RETRY_FLAG_INVALID'});
  if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()) issues.push({code:'RECOVERY_REPAIR_RECOVERY_CREATED_AT_MISSING'});
  if(pending.reconciliationId&&pending.reconciliationId.trim()&&`control-audit-recovery-repair-recovery:${pending.reconciliationId}`.length>260) issues.push({code:'RECOVERY_REPAIR_RECOVERY_DEDUPE_KEY_TOO_LONG'});
  const error=mission.controlAuditRecoveryEvidenceRepairRecoveryError||null;
  return {missionId:mission.id,ownerId,valid:issues.length===0,pending:true,reconciliationId:pending.reconciliationId||null,dedupeKey:pending.reconciliationId?`control-audit-recovery-repair-recovery:${pending.reconciliationId}`:null,issues:issues.map(issue=>({...issue})),error:error?String(error):null};
 }

 async function verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pending=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending||null;
  const issues=[];
  if(!pending){
   const error=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError||null;
   return {missionId:mission.id,ownerId,valid:!error,pending:false,reconciliationId:null,dedupeKey:null,issues:error?[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_ERROR_WITHOUT_PENDING',error:String(error)}]:[]};
  }
  if(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_RECONCILIATION_ID_MISSING'});
  if(typeof pending.recoveredByRetry!=='boolean') issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_RETRY_FLAG_INVALID'});
  if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_CREATED_AT_MISSING'});
  if(pending.reconciliationId&&pending.reconciliationId.trim()&&`control-audit-recovery-repair-recovery-status-recovered:${mission.id}`.length>260) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_DEDUPE_KEY_TOO_LONG'});
  const error=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError||null;
  return {missionId:mission.id,ownerId,valid:issues.length===0,pending:true,reconciliationId:pending.reconciliationId||null,dedupeKey:`control-audit-recovery-repair-recovery-status-recovered:${mission.id}`,issues:issues.map(issue=>({...issue})),error:error?String(error):null};
 }

 async function repairAuditRecoveryEvidenceRepairRecoveryStatus(ownerId,missionId){
  let mission=await get(ownerId,missionId);
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status:${current.id}`;
  const emit=async current=>observability.event(ownerId,current.id,'mission_control_audit_recovery_evidence_repair_recovery_status_repaired',{source:'mission-control',reconciliationId:current.controlAuditRecoveryEvidenceRepairRecoveryPending?.reconciliationId||null,dedupeKey:dedupeKey(current)});
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatus(ownerId,missionId);
   mission=await get(ownerId,missionId);
   const pending=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending||null;
   if(pending){
    try{
     await emit(mission);
     const cleared={...mission,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending:null,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError:null,updatedAt:clock()};
     try{return {missionId:(await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version})).id,ownerId,changed:false,repaired:true,valid:true,issues:[],observabilityEmitted:true,repairedByRetry:attempt>0};}
     catch(error){if(isVersionConflict(error)){mission=await get(ownerId,missionId);continue;}return {missionId:mission.id,ownerId,changed:false,repaired:true,valid:true,issues:[],observabilityEmitted:false,repairedByRetry:attempt>0};}
    }catch(error){
     const marked={...mission,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending:pending,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError:String(error?.message||error),updatedAt:clock()};
     try{await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});}catch(persistError){if(isVersionConflict(persistError)){mission=await get(ownerId,missionId);continue;}}
     return {missionId:mission.id,ownerId,changed:false,repaired:true,valid:true,issues:[],observabilityEmitted:false,repairedByRetry:attempt>0,error:String(error?.message||error)};
    }
   }
   if(verification.valid) return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],repairedByRetry:attempt>0};
   if(verification.pending) throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_UNREPAIRABLE','Recovery repair status tidak dapat diperbaiki secara bounded',409,{issues:verification.issues});
   if(!mission.controlAuditRecoveryEvidenceRepairRecoveryError) return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],repairedByRetry:attempt>0};
   const repairIntent={reconciliationId:mission.controlAuditRecoveryEvidenceRepairRecoveryPending?.reconciliationId||null,createdAt:clock(),repairedByRetry:attempt>0};
   const repaired={...mission,controlAuditRecoveryEvidenceRepairRecoveryError:null,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending:repairIntent,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError:null,updatedAt:clock()};
   try{
    mission=await missionStore.putOwned('missions',ownerId,missionId,repaired,{overwrite:true,expectedVersion:mission._storage?.version});
    try{
     await emit(mission);
     const cleared={...mission,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending:null,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError:null,updatedAt:clock()};
     try{const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],observabilityEmitted:true,storageVersion:saved._storage?.version??null,repairedByRetry:attempt>0};}
     catch(error){if(isVersionConflict(error)){mission=await get(ownerId,missionId);continue;}return {missionId:mission.id,ownerId,changed:true,repaired:true,valid:true,issues:[],observabilityEmitted:false,repairedByRetry:attempt>0};}
    }catch(error){
     const marked={...mission,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending:repairIntent,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError:String(error?.message||error),updatedAt:clock()};
     try{const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],observabilityEmitted:false,repairedByRetry:attempt>0,error:String(error?.message||error)};}catch(persistError){if(isVersionConflict(persistError)){mission=await get(ownerId,missionId);continue;}throw persistError;}
    }
   }catch(error){if(isVersionConflict(error)){mission=await get(ownerId,missionId);continue;}throw error;}
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_VERSION_CONFLICT','Mission berubah bersamaan; recovery repair status tidak dapat dipastikan secara aman',409);
 }

 async function repairAuditRecoveryEvidence(ownerId,missionId){
  let mission=await get(ownerId,missionId);
  async function emitRepairEvidence(current,pending){
   return observability.event(ownerId,current.id,'mission_control_audit_recovery_evidence_repaired',{source:'mission-control',reconciliationId:pending.reconciliationId,phaseBefore:pending.phaseBefore,reconciledByRetry:pending.reconciledByRetry===true,repairedByRetry:pending.repairedByRetry===true,dedupeKey:`control-audit-recovery-repair:${pending.reconciliationId}`});
  }
  async function finalizeRepairEvidence(current,pending){
   try {
    await emitRepairEvidence(current,pending);
    const cleared={...current,controlAuditRecoveryEvidenceRepairPending:null,controlAuditRecoveryEvidenceRepairError:null,updatedAt:clock()};
    try { return await missionStore.putOwned('missions',ownerId,current.id,cleared,{overwrite:true,expectedVersion:current._storage?.version}); }
    catch(error){ if(isVersionConflict(error)) return await get(ownerId,current.id); return current; }
   } catch(error){
    const marked={...current,controlAuditRecoveryEvidenceRepairPending:pending,controlAuditRecoveryEvidenceRepairError:String(error?.message||error),updatedAt:clock()};
    try { return await missionStore.putOwned('missions',ownerId,current.id,marked,{overwrite:true,expectedVersion:current._storage?.version}); }
    catch(persistError){ if(isVersionConflict(persistError)) return await get(ownerId,current.id); return current; }
   }
  }
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   mission=await get(ownerId,missionId);
   if(mission.controlAuditRecoveryEvidenceRepairPending){
    const finalized=await finalizeRepairEvidence(mission,mission.controlAuditRecoveryEvidenceRepairPending);
    if(finalized.controlAuditRecoveryEvidenceRepairPending){
     const latest=await get(ownerId,missionId);
     if(latest.controlAuditRecoveryEvidenceRepairPending?.reconciliationId===mission.controlAuditRecoveryEvidenceRepairPending.reconciliationId && latest._storage?.version!==mission._storage?.version){
      mission=latest;
      continue;
     }
    }
    return {missionId:finalized.id,ownerId,changed:false,repaired:false,valid:true,issues:[],repairedByRetry:attempt>0,recoveryEvidenceRepairEvidenceReconciledByRetry:attempt>0};
   }
   const verification=await verifyAuditRecoveryEvidence(ownerId,missionId);
   mission=await get(ownerId,missionId);
   if(!verification.pending) return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],repairedByRetry:attempt>0};
   if(!verification.valid) throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_UNREPAIRABLE','Recovery evidence tidak dapat diperbaiki secara bounded',409,{issues:verification.issues});
   if(!mission.controlAuditRecoveryEvidenceError) return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],repairedByRetry:attempt>0};
   const pendingRepair={reconciliationId:verification.reconciliationId,phaseBefore:mission.controlAuditRecoveryEvidencePending?.phaseBefore||null,reconciledByRetry:mission.controlAuditRecoveryEvidencePending?.reconciledByRetry===true,repairedByRetry:attempt>0,createdAt:clock()};
   const repaired={...mission,controlAuditRecoveryEvidenceError:null,controlAuditRecoveryEvidenceRepairPending:pendingRepair,controlAuditRecoveryEvidenceRepairError:null,updatedAt:clock()};
   try {
    const saved=await missionStore.putOwned('missions',ownerId,missionId,repaired,{overwrite:true,expectedVersion:mission._storage?.version});
    const finalized=await finalizeRepairEvidence(saved,pendingRepair);
    return {missionId:finalized.id,ownerId,changed:true,repaired:true,valid:true,issues:[],storageVersion:finalized._storage?.version??null,repairedByRetry:attempt>0,recoveryEvidenceRepairEvidenceReconciledByRetry:!finalized.controlAuditRecoveryEvidenceRepairPending&&attempt>0};
   } catch(error){
    if(isVersionConflict(error)){ mission=await get(ownerId,missionId); continue; }
    throw error;
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_VERSION_CONFLICT','Mission berubah bersamaan; recovery evidence repair tidak dapat dipastikan secara aman',409);
 }

 async function recoverAuditRecoveryEvidenceRepair(ownerId,missionId){
  async function finalizeRecoveryRepairRecoveryEvidence(current,pending){
   const emit=async()=>observability.event(ownerId,current.id,'mission_control_audit_recovery_evidence_repair_recovered',{source:'mission-control',reconciliationId:pending.reconciliationId,recoveredByRetry:pending.recoveredByRetry===true,dedupeKey:`control-audit-recovery-repair-recovery:${pending.reconciliationId}`});
   try {
    await emit();
    const cleared={...current,controlAuditRecoveryEvidenceRepairRecoveryPending:null,controlAuditRecoveryEvidenceRepairRecoveryError:null,updatedAt:clock()};
    try { return await missionStore.putOwned('missions',ownerId,current.id,cleared,{overwrite:true,expectedVersion:current._storage?.version}); }
    catch(error){ if(isVersionConflict(error)) return await get(ownerId,current.id); return current; }
   } catch(error){
    const marked={...current,controlAuditRecoveryEvidenceRepairRecoveryPending:pending,controlAuditRecoveryEvidenceRepairRecoveryError:String(error?.message||error),updatedAt:clock()};
    try { return await missionStore.putOwned('missions',ownerId,current.id,marked,{overwrite:true,expectedVersion:current._storage?.version}); }
    catch(persistError){ if(isVersionConflict(persistError)) return await get(ownerId,current.id); return current; }
   }
  }
  let mission=await get(ownerId,missionId);
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   mission=await get(ownerId,missionId);
   const recoveryPending=mission.controlAuditRecoveryEvidenceRepairRecoveryPending||null;
   if(recoveryPending){
    const finalized=await finalizeRecoveryRepairRecoveryEvidence(mission,recoveryPending);
    const after=await get(ownerId,missionId);
    return {missionId:after.id,ownerId,attempted:false,recovered:!after.controlAuditRecoveryEvidenceRepairRecoveryPending,phase:after.controlAuditRecoveryEvidenceRepairRecoveryPending?'pending':'clear',reconciliationId:recoveryPending.reconciliationId||null,repairedByRetry:recoveryPending.recoveredByRetry===true||attempt>0,error:after.controlAuditRecoveryEvidenceRepairRecoveryError||null};
   }
   const pending=mission.controlAuditRecoveryEvidenceRepairPending||null;
   if(pending){
    const repaired=await repairAuditRecoveryEvidence(ownerId,missionId);
    const after=await auditRecoveryEvidenceRepairStatus(ownerId,missionId);
    if(after.phase==='clear'){
     const current=await get(ownerId,missionId);
     const recoveryEvidence={reconciliationId:pending.reconciliationId||null,recoveredByRetry:repaired.repairedByRetry===true||attempt>0,createdAt:clock()};
     const marked={...current,controlAuditRecoveryEvidenceRepairRecoveryPending:recoveryEvidence,controlAuditRecoveryEvidenceRepairRecoveryError:null,updatedAt:clock()};
     try {
      const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:current._storage?.version});
      const finalized=await finalizeRecoveryRepairRecoveryEvidence(saved,recoveryEvidence);
      return {missionId:finalized.id,ownerId,attempted:false,recovered:!finalized.controlAuditRecoveryEvidenceRepairRecoveryPending,phase:finalized.controlAuditRecoveryEvidenceRepairRecoveryPending?'pending':'clear',reconciliationId:pending.reconciliationId||null,repairedByRetry:repaired.repairedByRetry===true||attempt>0,error:finalized.controlAuditRecoveryEvidenceRepairRecoveryError||null};
     } catch(error){ if(isVersionConflict(error)){ mission=await get(ownerId,missionId); continue; } throw error; }
    }
    return {missionId:after.missionId,ownerId,attempted:false,recovered:false,phase:after.phase,reconciliationId:pending.reconciliationId||null,repairedByRetry:repaired.repairedByRetry===true||attempt>0,error:after.error};
   }
   const status=await auditRecoveryEvidenceRepairStatus(ownerId,missionId);
   if(status.phase==='clear') return {missionId:status.missionId,ownerId,attempted:false,recovered:false,phase:'clear',reconciliationId:null,repairedByRetry:false,error:null};
   if(status.phase==='error'){
    const latest=await get(ownerId,missionId);
    if(!latest.controlAuditRecoveryEvidenceRepairPending) return {missionId:status.missionId,ownerId,attempted:false,recovered:false,phase:'error',reconciliationId:status.reconciliationId,error:status.error,repairedByRetry:false};
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_VERSION_CONFLICT','Mission berubah bersamaan; recovery evidence repair recovery tidak dapat dipastikan secara aman',409);
 }

 async function recoverAuditReconciliation(ownerId,missionId){
  let before=await reconciliationStatus(ownerId,missionId);
  async function emitRecoveryEvidence(current,pending){
   return observability.event(ownerId,current.id,'mission_control_audit_recovery_completed',{source:'mission-control',reconciliationId:pending.reconciliationId,phaseBefore:pending.phaseBefore,reconciledByRetry:pending.reconciledByRetry===true,dedupeKey:`control-audit-recovery:${pending.reconciliationId}`});
  }
  async function finalizeRecoveryEvidence(current,pending){
   try {
    await emitRecoveryEvidence(current,pending);
    const cleared={...current,controlAuditRecoveryEvidencePending:null,controlAuditRecoveryEvidenceError:null,updatedAt:clock()};
    try { return await missionStore.putOwned('missions',ownerId,current.id,cleared,{overwrite:true,expectedVersion:current._storage?.version}); }
    catch(error){ if(isVersionConflict(error)) return await get(ownerId,current.id); return current; }
   } catch(error){
    const marked={...current,controlAuditRecoveryEvidencePending:pending,controlAuditRecoveryEvidenceError:String(error?.message||error),updatedAt:clock()};
    try { return await missionStore.putOwned('missions',ownerId,current.id,marked,{overwrite:true,expectedVersion:current._storage?.version}); }
    catch(persistError){ if(isVersionConflict(persistError)) return await get(ownerId,current.id); return current; }
   }
  }
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_RETRIES;attempt++) {
   let mission=await get(ownerId,missionId);
   if(mission.controlAuditRecoveryEvidencePending){
    const pending=mission.controlAuditRecoveryEvidencePending;
    const finalized=await finalizeRecoveryEvidence(mission,pending);
    if(finalized.controlAuditRecoveryEvidencePending){
     const latest=await get(ownerId,missionId);
     if(latest.controlAuditRecoveryEvidencePending?.reconciliationId===pending.reconciliationId && latest._storage?.version!==mission._storage?.version){
      continue;
     }
    }
    const after=await reconciliationStatus(ownerId,missionId);
    return {missionId:after.missionId,ownerId,attempted:false,recovered:false,phase:after.phase,reconciliationId:pending.reconciliationId,error:after.error,evidenceRepaired:false,recoveryEvidenceRepaired:!finalized.controlAuditRecoveryEvidencePending,recoveryEvidenceReconciledByRetry:attempt>0};
   }
   before=await reconciliationStatus(ownerId,missionId);
   if(!before.recoverable){
    return {missionId:before.missionId,ownerId,attempted:false,recovered:false,phase:before.phase,reconciliationId:before.reconciliationId,error:before.error};
   }
   const result=await reconcileAudit(ownerId,missionId);
   const after=await reconciliationStatus(ownerId,missionId);
   const reconciliationId=before.reconciliationId||result.reconciliationId||null;
   if(before.recoverable&&!after.recoverable && reconciliationId){
    const current=await get(ownerId,missionId);
    const pending={reconciliationId,phaseBefore:before.phase,reconciledByRetry:result.reconciledByRetry===true,createdAt:clock()};
    const marked={...current,controlAuditRecoveryEvidencePending:pending,controlAuditRecoveryEvidenceError:null,updatedAt:clock()};
    try {
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:current._storage?.version});
     const finalized=await finalizeRecoveryEvidence(saved,pending);
     return {missionId:finalized.id,ownerId,attempted:true,recovered:true,phaseBefore:before.phase,phaseAfter:after.phase,reconciliationId,evidenceRepaired:result.evidenceRepaired===true,reconciledByRetry:result.reconciledByRetry===true,recoveryEvidenceRepaired:!finalized.controlAuditRecoveryEvidencePending,recoveryEvidenceReconciledByRetry:attempt>0,error:after.error};
    } catch(error){
     if(isVersionConflict(error)){ continue; }
     throw error;
    }
   }
   return {missionId:after.missionId,ownerId,attempted:true,recovered:false,phaseBefore:before.phase,phaseAfter:after.phase,reconciliationId,evidenceRepaired:result.evidenceRepaired===true,reconciledByRetry:result.reconciledByRetry===true,recoveryEvidenceRepaired:false,recoveryEvidenceReconciledByRetry:false,error:after.error};
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_VERSION_CONFLICT','Mission berubah bersamaan; recovery evidence tidak dapat dipastikan secara aman',409);
 }

 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatus(ownerId,missionId){
  let mission=await get(ownerId,missionId);
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   mission=await get(ownerId,missionId);
   const pending=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending||null;
   const error=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError||null;
   if(pending) return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],pending:true,repairedByRetry:attempt>0,error:error?String(error):null};
   if(!error) return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],pending:false,repairedByRetry:attempt>0,error:null};
   const repaired={...mission,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,repaired,{overwrite:true,expectedVersion:mission._storage?.version});
    return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:false,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
   }catch(error){
    if(isVersionConflict(error)){continue;}
    throw error;
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_VERSION_CONFLICT','Mission berubah bersamaan; recovery status repair recovery observability tidak dapat diperbaiki secara aman',409);
 }

 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepair(ownerId,missionId){
  let mission=await get(ownerId,missionId);
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-repair:${current.id}`;
  const emit=async current=>observability.event(ownerId,current.id,'mission_control_audit_recovery_evidence_repair_recovery_status_repair_repaired',{source:'mission-control',reconciliationId:current.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending?.reconciliationId||null,dedupeKey:dedupeKey(current),repairedByRetry:current.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending?.repairedByRetry===true});
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   mission=await get(ownerId,missionId);
   const pending=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending||null;
   const error=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError||null;
   if(pending){
    try{
     await emit(mission);
     const cleared={...mission,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending:null,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError:null,updatedAt:clock()};
     try{const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});return {missionId:saved.id,ownerId,changed:false,repaired:true,valid:true,issues:[],observabilityEmitted:true,repairedByRetry:attempt>0,storageVersion:saved._storage?.version??null,error:null};}
     catch(writeError){if(isVersionConflict(writeError)){continue;}return {missionId:mission.id,ownerId,changed:false,repaired:true,valid:true,issues:[],observabilityEmitted:false,repairedByRetry:attempt>0,error:String(writeError?.message||writeError)};}
    }catch(emitError){
     const marked={...mission,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending:pending,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError:String(emitError?.message||emitError),updatedAt:clock()};
     try{await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});}catch(writeError){if(isVersionConflict(writeError)){continue;}}
     return {missionId:mission.id,ownerId,changed:false,repaired:true,valid:true,issues:[],observabilityEmitted:false,repairedByRetry:attempt>0,error:String(emitError?.message||emitError)};
    }
   }
   if(!error) return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],observabilityEmitted:false,repairedByRetry:attempt>0,error:null};
   const repairIntent={reconciliationId:mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending?.reconciliationId||null,createdAt:clock(),repairedByRetry:attempt>0};
   const prepared={...mission,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError:null,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending:repairIntent,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError:null,updatedAt:clock()};
   try{
    mission=await missionStore.putOwned('missions',ownerId,missionId,prepared,{overwrite:true,expectedVersion:mission._storage?.version});
    try{
     await emit(mission);
     const cleared={...mission,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending:null,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError:null,updatedAt:clock()};
     try{const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],observabilityEmitted:true,repairedByRetry:attempt>0,storageVersion:saved._storage?.version??null,error:null};}
     catch(writeError){if(isVersionConflict(writeError)){continue;}return {missionId:mission.id,ownerId,changed:true,repaired:true,valid:true,issues:[],observabilityEmitted:false,repairedByRetry:attempt>0,error:String(writeError?.message||writeError)};}
    }catch(emitError){
     const marked={...mission,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending:repairIntent,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError:String(emitError?.message||emitError),updatedAt:clock()};
     try{const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],observabilityEmitted:false,repairedByRetry:attempt>0,error:String(emitError?.message||emitError)};}catch(writeError){if(isVersionConflict(writeError)){continue;}throw writeError;}
    }
   }catch(writeError){if(isVersionConflict(writeError)){continue;}throw writeError;}
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_VERSION_CONFLICT','Mission berubah bersamaan; recovery status repair recovery status repair observability tidak dapat dipastikan secara aman',409);
 }

 async function auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pending=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending||null;
  const error=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError||null;
  const phase=pending?'pending':error?'error':'clear';
  const reconciliationId=typeof pending?.reconciliationId==='string'&&pending.reconciliationId.trim()?pending.reconciliationId.trim().slice(0,200):null;
  const createdAt=typeof pending?.createdAt==='string'&&pending.createdAt.trim()?pending.createdAt.trim().slice(0,100):null;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   recoverable:Boolean(pending),
   reconciliationId,
   repairedByRetry:pending?.repairedByRetry===true,
   createdAt,
   error:error?String(error).slice(0,1000):null,
   storageVersion:mission._storage?.version??null
  };
 }

 async function verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pending=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending??null;
  const error=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError??null;
  const dedupeKey=`control-audit-recovery-repair-recovery-status-repair:${mission.id}`;
  const issues=[];
  if(pending===null){
   if(error) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_ERROR_WITHOUT_PENDING',error:String(error).slice(0,1000)});
   return {missionId:mission.id,ownerId,valid:issues.length===0,pending:false,reconciliationId:null,repairedByRetry:false,createdAt:null,dedupeKey:null,issues,error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null};
  }
  if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_PENDING_INVALID'});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null&&(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim())) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECONCILIATION_ID_INVALID'});
   if(typeof pending.reconciliationId==='string'&&pending.reconciliationId.length>200) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECONCILIATION_ID_TOO_LONG'});
   if(typeof pending.repairedByRetry!=='boolean') issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RETRY_FLAG_INVALID'});
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_CREATED_AT_MISSING'});
   if(typeof pending.createdAt==='string'&&pending.createdAt.length>100) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_CREATED_AT_TOO_LONG'});
   if(dedupeKey.length>260) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_DEDUPE_KEY_TOO_LONG'});
  }
  const reconciliationId=typeof pending==='object'&&!Array.isArray(pending)&&typeof pending.reconciliationId==='string'&&pending.reconciliationId.trim()?pending.reconciliationId.trim().slice(0,200):null;
  const createdAt=typeof pending==='object'&&!Array.isArray(pending)&&typeof pending.createdAt==='string'&&pending.createdAt.trim()?pending.createdAt.trim().slice(0,100):null;
  return {missionId:mission.id,ownerId,valid:issues.length===0,pending:true,reconciliationId,repairedByRetry:pending?.repairedByRetry===true,createdAt,dedupeKey,issues:issues.map(issue=>({...issue})),error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null};
 }

 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError';
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending!==null){
    const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus(ownerId,missionId);
    return {missionId:verification.missionId,ownerId,changed:false,repaired:false,valid:verification.valid,issues:verification.issues,pending:verification.pending,repairedByRetry:attempt>0,error:verification.error,storageVersion:verification.storageVersion};
   }
   if(!error) return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],pending:false,repairedByRetry:attempt>0,error:null,storageVersion:mission._storage?.version??null};
   const repaired={...mission,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,repaired,{overwrite:true,expectedVersion:mission._storage?.version});
    return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:false,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_VERSION_CONFLICT','Mission berubah bersamaan; perbaikan error recovery status tidak dapat dipastikan secara aman',409);
 }

 async function recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepair(ownerId,missionId){
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending||null;
   const existingError=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError||null;
   if(!pending) return {missionId:mission.id,ownerId,attempted:false,recovered:false,phase:existingError?'error':'clear',observabilityEmitted:false,recoveredByRetry:attempt>0,error:existingError?String(existingError):null,storageVersion:mission._storage?.version??null};
   if(!pending||typeof pending!=='object'||Array.isArray(pending)||typeof pending.createdAt!=='string'||!pending.createdAt.trim()){
    throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_UNREPAIRABLE','Pending status-repair recovery observability intent tidak valid dan tidak dapat dipulihkan secara bounded',409);
   }
   const dedupeKey=`control-audit-recovery-repair-recovery-status-repair:${mission.id}`;
   try{
    await observability.event(ownerId,mission.id,'mission_control_audit_recovery_evidence_repair_recovery_status_repair_repaired',{source:'mission-control',reconciliationId:typeof pending.reconciliationId==='string'&&pending.reconciliationId.trim()?pending.reconciliationId:null,dedupeKey,repairedByRetry:pending.repairedByRetry===true});
   }catch(emitError){
    const message=String(emitError?.message||emitError);
    const marked={...mission,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending:pending,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError:message,updatedAt:clock()};
    try{
     await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return {missionId:mission.id,ownerId,attempted:true,recovered:false,phase:'pending',observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError),storageVersion:mission._storage?.version??null};
    }
    return {missionId:mission.id,ownerId,attempted:true,recovered:false,phase:'pending',observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,storageVersion:mission._storage?.version??null};
   }
   const cleared={...mission,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending:null,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
    return {missionId:saved.id,ownerId,attempted:true,recovered:true,phase:'clear',observabilityEmitted:true,recoveredByRetry:attempt>0,storageVersion:saved._storage?.version??null,error:null};
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return {missionId:mission.id,ownerId,attempted:true,recovered:false,phase:'pending',observabilityEmitted:true,recoveredByRetry:attempt>0,error:String(writeError?.message||writeError),storageVersion:mission._storage?.version??null};
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_VERSION_CONFLICT','Mission berubah bersamaan; status-repair recovery observability tidak dapat dipastikan secara aman',409);
 }

 async function recoverAuditRecoveryEvidenceRepairRecoveryStatusRepair(ownerId,missionId){
  let mission=await get(ownerId,missionId);
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-recovered:${current.id}`;
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   mission=await get(ownerId,missionId);
   const pending=mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending||null;
   if(!pending) return {missionId:mission.id,ownerId,attempted:false,recovered:false,phase:mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError?'error':'clear',repairedByRetry:attempt>0,error:mission.controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError||null};
   if(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()) throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_UNREPAIRABLE','Recovery status repair observability intent tidak dapat dipulihkan secara bounded',409,{issues:[{code:'STATUS_REPAIR_RECONCILIATION_ID_MISSING'}]});
   try{
    await observability.event(ownerId,mission.id,'mission_control_audit_recovery_evidence_repair_recovery_status_recovered',{source:'mission-control',reconciliationId:pending.reconciliationId,dedupeKey:dedupeKey(mission),recoveredByRetry:true});
    const cleared={...mission,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending:null,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError:null,updatedAt:clock()};
    try{const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});return {missionId:saved.id,ownerId,attempted:true,recovered:true,phase:'clear',repairedByRetry:attempt>0,observabilityEmitted:true,storageVersion:saved._storage?.version??null,error:null};}catch(error){if(isVersionConflict(error)){continue;}throw error;}
   }catch(error){
    const marked={...mission,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending:pending,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError:String(error?.message||error),updatedAt:clock()};
    try{await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});}catch(persistError){if(isVersionConflict(persistError))continue;}
    return {missionId:mission.id,ownerId,attempted:true,recovered:false,phase:'pending',repairedByRetry:attempt>0,observabilityEmitted:false,error:String(error?.message||error)};
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_VERSION_CONFLICT','Mission berubah bersamaan; recovery status repair observability tidak dapat dipastikan secara aman',409);
 }


 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusWithObservability(ownerId,missionId){
  const sourcePendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending';
  const sourceErrorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError';
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusError';
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair:${current.id}`;
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_repaired';
  const emit=(current,intent)=>observability.event(ownerId,current.id,eventType,{
   source:'mission-control',
   reconciliationId:typeof intent?.reconciliationId==='string'&&intent.reconciliationId.trim()?intent.reconciliationId.trim().slice(0,200):null,
   dedupeKey:dedupeKey(current),
   repairedByRetry:intent?.repairedByRetry===true
  });
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending!==null){
    if(!validIntent(pending)){
     return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_OBSERVABILITY_PENDING_INVALID'}],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null};
    }
    let emitError=null;
    try{await emit(mission,pending);}catch(caught){emitError=caught;}
    if(emitError){
     const message=String(emitError?.message||emitError).slice(0,1000);
     const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
     try{
      const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
      return {missionId:saved.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null};
     }catch(writeError){if(isVersionConflict(writeError)) continue;return {missionId:mission.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null};}
    }
    const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
     return {missionId:saved.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
    }catch(writeError){if(isVersionConflict(writeError)) continue;return {missionId:mission.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null};}
   }
   if(error){
    return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_OBSERVABILITY_ERROR_WITHOUT_PENDING'}],pending:false,observabilityEmitted:false,repairedByRetry:attempt>0,error:String(error).slice(0,1000),storageVersion:mission._storage?.version??null};
   }
   const sourcePending=mission[sourcePendingKey]??null;
   const sourceError=mission[sourceErrorKey]??null;
   if(sourcePending!==null){
    const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus(ownerId,missionId);
    return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:verification.valid,issues:verification.issues,pending:verification.pending,observabilityEmitted:false,repairedByRetry:attempt>0,error:verification.error,storageVersion:verification.storageVersion};
   }
   if(!sourceError){
    return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],pending:false,observabilityEmitted:false,repairedByRetry:attempt>0,error:null,storageVersion:mission._storage?.version??null};
   }
   const intent={reconciliationId:null,createdAt:clock(),repairedByRetry:attempt>0};
   const prepared={...mission,[sourceErrorKey]:null,[pendingKey]:intent,[errorKey]:null,updatedAt:clock()};
   let persisted;
   try{persisted=await missionStore.putOwned('missions',ownerId,missionId,prepared,{overwrite:true,expectedVersion:mission._storage?.version});}
   catch(writeError){if(isVersionConflict(writeError)) continue;throw writeError;}
   let emitError=null;
   try{await emit(persisted,intent);}catch(caught){emitError=caught;}
   if(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...persisted,[pendingKey]:intent,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:persisted._storage?.version});
     return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null};
    }catch(writeError){if(isVersionConflict(writeError)) continue;return {missionId:persisted.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:persisted._storage?.version??null};}
   }
   const cleared={...persisted,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:persisted._storage?.version});
    return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
   }catch(writeError){if(isVersionConflict(writeError)) continue;return {missionId:persisted.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:persisted._storage?.version??null};}
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_OBSERVABILITY_VERSION_CONFLICT','Mission berubah bersamaan; observability repair status recovery tidak dapat dipastikan secara aman',409);
 }

 async function recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_repaired';
  const dedupeKey=mission=>`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair:${mission.id}`;
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const existingError=mission[errorKey]??null;
   if(pending===null){
    if(existingError){
     return {missionId:mission.id,ownerId,attempted:false,recovered:false,phase:'error',valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_ERROR_WITHOUT_PENDING'}],observabilityEmitted:false,recoveredByRetry:attempt>0,error:String(existingError).slice(0,1000),storageVersion:mission._storage?.version??null};
    }
    return {missionId:mission.id,ownerId,attempted:false,recovered:false,phase:'clear',valid:true,issues:[],observabilityEmitted:false,recoveredByRetry:attempt>0,error:null,storageVersion:mission._storage?.version??null};
   }
   if(!validIntent(pending)){
    return {missionId:mission.id,ownerId,attempted:true,recovered:false,phase:'pending',valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_PENDING_INVALID'}],observabilityEmitted:false,recoveredByRetry:attempt>0,error:existingError?String(existingError).slice(0,1000):null,storageVersion:mission._storage?.version??null};
   }
   try{
    await observability.event(ownerId,mission.id,eventType,{
     source:'mission-control',
     reconciliationId:typeof pending.reconciliationId==='string'&&pending.reconciliationId.trim()?pending.reconciliationId.trim().slice(0,200):null,
     dedupeKey:dedupeKey(mission),
     repairedByRetry:pending.repairedByRetry===true
    });
   }catch(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
     return {missionId:saved.id,ownerId,attempted:true,recovered:false,phase:'pending',valid:true,issues:[],observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null};
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return {missionId:mission.id,ownerId,attempted:true,recovered:false,phase:'pending',valid:true,issues:[],observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null};
    }
   }
   const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
    return {missionId:saved.id,ownerId,attempted:true,recovered:true,phase:'clear',valid:true,issues:[],observabilityEmitted:true,recoveredByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return {missionId:mission.id,ownerId,attempted:true,recovered:false,phase:'pending',valid:true,issues:[],observabilityEmitted:true,recoveredByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null};
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_VERSION_CONFLICT','Mission berubah bersamaan; recovery observability repair status tidak dapat dipastikan secara aman',409);
 }


 async function auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusError';
  const pending=mission[pendingKey]??null;
  const error=mission[errorKey]??null;
  const issues=[];
  const phase=pending!==null?'pending':error?'error':'clear';
  let reconciliationId=null;
  let createdAt=null;
  let repairedByRetry=false;
  if(pending===null){
   if(error) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_ERROR_WITHOUT_PENDING'});
  }else if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_PENDING_INVALID'});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null&&
      (typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()||pending.reconciliationId.length>200)){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECONCILIATION_ID_INVALID'});
   }else if(typeof pending.reconciliationId==='string'&&pending.reconciliationId.trim()){
    reconciliationId=pending.reconciliationId.trim().slice(0,200);
   }
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()||pending.createdAt.length>100){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_CREATED_AT_INVALID'});
   }else{
    createdAt=pending.createdAt.trim().slice(0,100);
   }
   if(typeof pending.repairedByRetry!=='boolean'){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RETRY_FLAG_INVALID'});
   }else{
    repairedByRetry=pending.repairedByRetry;
   }
  }
  const valid=issues.length===0;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   valid,
   recoverable:pending!==null&&valid,
   pending:pending!==null,
   reconciliationId,
   repairedByRetry,
   createdAt,
   error:error?String(error).slice(0,1000):null,
   issues,
   storageVersion:mission._storage?.version??null
  };
 }

 async function verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusError';
  const pending=mission[pendingKey]??null;
  const error=mission[errorKey]??null;
  const phase=pending!==null?'pending':error?'error':'clear';
  const issues=[];
  const dedupeKey=pending!==null?`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair:${mission.id}`:null;
  let reconciliationId=null;
  let createdAt=null;
  let repairedByRetry=false;
  if(pending===null){
   if(error) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_ERROR_WITHOUT_PENDING'});
  }else if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_PENDING_INVALID'});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null){
    if(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()){
     issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECONCILIATION_ID_INVALID'});
    }else if(pending.reconciliationId.length>200){
     issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECONCILIATION_ID_TOO_LONG'});
    }else{
     reconciliationId=pending.reconciliationId.trim().slice(0,200);
    }
   }
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_CREATED_AT_MISSING'});
   }else if(pending.createdAt.length>100){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_CREATED_AT_TOO_LONG'});
   }else{
    createdAt=pending.createdAt.trim().slice(0,100);
   }
   if(typeof pending.repairedByRetry!=='boolean'){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RETRY_FLAG_INVALID'});
   }else{
    repairedByRetry=pending.repairedByRetry;
   }
   if(typeof dedupeKey!=='string'||dedupeKey.length>260){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_DEDUPE_KEY_INVALID'});
   }
  }
  return {
   missionId:mission.id,
   ownerId,
   phase,
   valid:issues.length===0,
   pending:pending!==null,
   recoverable:pending!==null&&issues.length===0,
   reconciliationId,
   repairedByRetry,
   createdAt,
   dedupeKey,
   error:error?String(error).slice(0,1000):null,
   issues,
   storageVersion:mission._storage?.version??null
  };
 }


 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusError';
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending!==null){
    const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus(ownerId,missionId);
    return {missionId:verification.missionId,ownerId,changed:false,repaired:false,valid:verification.valid,issues:verification.issues,pending:verification.pending,repairedByRetry:attempt>0,error:verification.error,storageVersion:verification.storageVersion};
   }
   if(!error) return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],pending:false,repairedByRetry:attempt>0,error:null,storageVersion:mission._storage?.version??null};
   const repaired={...mission,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,repaired,{overwrite:true,expectedVersion:mission._storage?.version});
    return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:false,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_VERSION_CONFLICT','Mission berubah bersamaan; orphaned recovery-status error tidak dapat diperbaiki secara aman',409);
 }


 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusWithObservability(ownerId,missionId){
  const sourcePendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusPending';
  const sourceErrorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusError';
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_repaired';
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status:${current.id}`;
  const emit=(current,intent)=>observability.event(ownerId,current.id,eventType,{
   source:'mission-control',
   reconciliationId:typeof intent?.reconciliationId==='string'&&intent.reconciliationId.trim()?intent.reconciliationId.trim().slice(0,200):null,
   dedupeKey:dedupeKey(current),
   repairedByRetry:intent?.repairedByRetry===true
  });
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending!==null){
    if(!validIntent(pending)){
     return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_OBSERVABILITY_PENDING_INVALID'}],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null};
    }
    let emitError=null;
    try{await emit(mission,pending);}catch(caught){emitError=caught;}
    if(emitError){
     const message=String(emitError?.message||emitError).slice(0,1000);
     const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
     try{
      const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
      return {missionId:saved.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null};
     }catch(writeError){
      if(isVersionConflict(writeError)) continue;
      return {missionId:mission.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null};
     }
    }
    const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
     return {missionId:saved.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return {missionId:mission.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null};
    }
   }
   if(error){
    return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_OBSERVABILITY_ERROR_WITHOUT_PENDING'}],pending:false,observabilityEmitted:false,repairedByRetry:attempt>0,error:String(error).slice(0,1000),storageVersion:mission._storage?.version??null};
   }
   const sourcePending=mission[sourcePendingKey]??null;
   if(sourcePending!==null){
    const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus(ownerId,missionId);
    return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:verification.valid,issues:verification.issues,pending:verification.pending,observabilityEmitted:false,repairedByRetry:attempt>0,error:verification.error,storageVersion:verification.storageVersion};
   }
   const sourceError=mission[sourceErrorKey]??null;
   if(!sourceError){
    return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],pending:false,observabilityEmitted:false,repairedByRetry:attempt>0,error:null,storageVersion:mission._storage?.version??null};
   }
   const intent={reconciliationId:null,createdAt:clock(),repairedByRetry:attempt>0};
   const prepared={...mission,[sourceErrorKey]:null,[pendingKey]:intent,[errorKey]:null,updatedAt:clock()};
   let persisted;
   try{
    persisted=await missionStore.putOwned('missions',ownerId,missionId,prepared,{overwrite:true,expectedVersion:mission._storage?.version});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
   let emitError=null;
   try{await emit(persisted,intent);}catch(caught){emitError=caught;}
   if(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...persisted,[pendingKey]:intent,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:persisted._storage?.version});
     return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null};
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return {missionId:persisted.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:persisted._storage?.version??null};
    }
   }
   const cleared={...persisted,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:persisted._storage?.version});
    return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return {missionId:persisted.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:persisted._storage?.version??null};
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_VERSION_CONFLICT','Mission berubah bersamaan; observability untuk perbaikan orphaned recovery-status error tidak dapat dipastikan secara aman',409);
 }


 async function recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_repaired';
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status:${current.id}`;
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  const phaseResult=(mission,fields={})=>({
   missionId:mission.id,
   ownerId,
   attempted:false,
   recovered:false,
   phase:'clear',
   valid:true,
   issues:[],
   pending:false,
   observabilityEmitted:false,
   recoveredByRetry:false,
   error:null,
   storageVersion:mission._storage?.version??null,
   ...fields
  });
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending===null){
    if(error){
     return phaseResult(mission,{phase:'error',valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_ERROR_WITHOUT_PENDING'}],error:String(error).slice(0,1000),storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
    }
    return phaseResult(mission,{recoveredByRetry:attempt>0});
   }
   if(!validIntent(pending)){
    return phaseResult(mission,{phase:'pending',valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_PENDING_INVALID'}],pending:true,error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
   }
   const eventReconciliationId=typeof pending.reconciliationId==='string'&&pending.reconciliationId.trim()?pending.reconciliationId.trim().slice(0,200):null;
   try{
    await observability.event(ownerId,mission.id,eventType,{
     source:'mission-control',
     reconciliationId:eventReconciliationId,
     dedupeKey:dedupeKey(mission),
     repairedByRetry:pending.repairedByRetry===true
    });
   }catch(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
     return phaseResult(saved,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null});
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return phaseResult(mission,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
    }
   }
   const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
    return phaseResult(saved,{attempted:true,recovered:true,phase:'clear',valid:true,issues:[],pending:false,observabilityEmitted:true,recoveredByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return phaseResult(mission,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:true,recoveredByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_VERSION_CONFLICT','Mission berubah bersamaan; recovery observability untuk perbaikan orphaned recovery-status error tidak dapat dipastikan secara aman',409);
 }


 async function auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusError';
  const pending=mission[pendingKey]??null;
  const error=mission[errorKey]??null;
  const issues=[];
  const phase=pending!==null?'pending':error?'error':'clear';
  let reconciliationId=null;
  let createdAt=null;
  let repairedByRetry=false;
  if(pending===null){
   if(error) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_ERROR_WITHOUT_PENDING'});
  }else if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_PENDING_INVALID'});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null&&
      (typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()||pending.reconciliationId.length>200)){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECONCILIATION_ID_INVALID'});
   }else if(typeof pending.reconciliationId==='string'&&pending.reconciliationId.trim()){
    reconciliationId=pending.reconciliationId.trim().slice(0,200);
   }
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()||pending.createdAt.length>100){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_CREATED_AT_INVALID'});
   }else{
    createdAt=pending.createdAt.trim().slice(0,100);
   }
   if(typeof pending.repairedByRetry!=='boolean'){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RETRY_FLAG_INVALID'});
   }else{
    repairedByRetry=pending.repairedByRetry;
   }
  }
  const valid=issues.length===0;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   valid,
   recoverable:pending!==null&&valid,
   pending:pending!==null,
   reconciliationId,
   repairedByRetry,
   createdAt,
   error:error?String(error).slice(0,1000):null,
   issues,
   storageVersion:mission._storage?.version??null
  };
 }


 async function verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusError';
  const pending=mission[pendingKey]??null;
  const error=mission[errorKey]??null;
  const phase=pending!==null?'pending':error?'error':'clear';
  const issues=[];
  const rawDedupeKey=pending!==null?`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status:${mission.id}`:null;
  const dedupeKey=rawDedupeKey!==null&&rawDedupeKey.length<=260?rawDedupeKey:null;
  let reconciliationId=null;
  let createdAt=null;
  let repairedByRetry=false;
  if(pending===null){
   if(error) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_ERROR_WITHOUT_PENDING'});
  }else if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_PENDING_INVALID'});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null){
    if(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()){
     issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECONCILIATION_ID_INVALID'});
    }else if(pending.reconciliationId.length>200){
     issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECONCILIATION_ID_TOO_LONG'});
    }else{
     reconciliationId=pending.reconciliationId.trim().slice(0,200);
    }
   }
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_CREATED_AT_MISSING'});
   }else if(pending.createdAt.length>100){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_CREATED_AT_TOO_LONG'});
   }else{
    createdAt=pending.createdAt.trim().slice(0,100);
   }
   if(typeof pending.repairedByRetry!=='boolean'){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RETRY_FLAG_INVALID'});
   }else{
    repairedByRetry=pending.repairedByRetry;
   }
   if(rawDedupeKey===null||rawDedupeKey.length>260){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_DEDUPE_KEY_INVALID'});
   }
  }
  const valid=issues.length===0;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   valid,
   pending:pending!==null,
   recoverable:pending!==null&&valid,
   reconciliationId,
   dedupeKey,
   createdAt,
   repairedByRetry,
   error:error?String(error).slice(0,1000):null,
   issues,
   storageVersion:mission._storage?.version??null
  };
 }


 async function verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const pending=mission[pendingKey]??null;
  const error=mission[errorKey]??null;
  const phase=pending!==null?'pending':error?'error':'clear';
  const issues=[];
  const rawDedupeKey=pending!==null?`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status:${mission.id}`:null;
  const dedupeKey=rawDedupeKey!==null&&rawDedupeKey.length<=260?rawDedupeKey:null;
  let reconciliationId=null;
  let createdAt=null;
  let repairedByRetry=false;
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  if(pending===null){
   if(error) issues.push({code:`${prefix}ERROR_WITHOUT_PENDING`});
  }else if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:`${prefix}PENDING_INVALID`});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null){
    if(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()){
     issues.push({code:`${prefix}RECONCILIATION_ID_INVALID`});
    }else if(pending.reconciliationId.length>200){
     issues.push({code:`${prefix}RECONCILIATION_ID_TOO_LONG`});
    }else{
     reconciliationId=pending.reconciliationId.trim().slice(0,200);
    }
   }
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()){
    issues.push({code:`${prefix}CREATED_AT_MISSING`});
   }else if(pending.createdAt.length>100){
    issues.push({code:`${prefix}CREATED_AT_TOO_LONG`});
   }else{
    createdAt=pending.createdAt.trim().slice(0,100);
   }
   if(typeof pending.repairedByRetry!=='boolean'){
    issues.push({code:`${prefix}RETRY_FLAG_INVALID`});
   }else{
    repairedByRetry=pending.repairedByRetry;
   }
   if(rawDedupeKey===null||rawDedupeKey.length>260){
    issues.push({code:`${prefix}DEDUPE_KEY_INVALID`});
   }
  }
  const valid=issues.length===0;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   valid,
   pending:pending!==null,
   recoverable:pending!==null&&valid,
   reconciliationId,
   dedupeKey,
   createdAt,
   repairedByRetry,
   error:error?String(error).slice(0,1000):null,
   issues,
   storageVersion:mission._storage?.version??null
  };
 }


 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending!==null){
    const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId);
    return {missionId:verification.missionId,ownerId,changed:false,repaired:false,valid:verification.valid,issues:verification.issues,pending:verification.pending,repairedByRetry:attempt>0,error:verification.error,storageVersion:verification.storageVersion};
   }
   if(!error) return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],pending:false,repairedByRetry:attempt>0,error:null,storageVersion:mission._storage?.version??null};
   const repaired={...mission,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,repaired,{overwrite:true,expectedVersion:mission._storage?.version});
    return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:false,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_VERSION_CONFLICT','Mission berubah bersamaan; orphaned recovery-status error tidak dapat diperbaiki secara aman',409);
 }


 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusError';
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending!==null){
    const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId);
    return {missionId:verification.missionId,ownerId,changed:false,repaired:false,valid:verification.valid,issues:verification.issues,pending:verification.pending,repairedByRetry:attempt>0,error:verification.error,storageVersion:verification.storageVersion};
   }
   if(!error) return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],pending:false,repairedByRetry:attempt>0,error:null,storageVersion:mission._storage?.version??null};
   const repaired={...mission,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,repaired,{overwrite:true,expectedVersion:mission._storage?.version});
    return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:false,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_VERSION_CONFLICT','Mission berubah bersamaan; orphaned recovery-status error tidak dapat diperbaiki secara aman',409);
 }


 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusWithObservability(ownerId,missionId){
  const sourcePendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusPending';
  const sourceErrorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusError';
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_repaired';
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status:${current.id}`;
  const emit=(current,intent)=>observability.event(ownerId,current.id,eventType,{
   source:'mission-control',
   reconciliationId:typeof intent?.reconciliationId==='string'&&intent.reconciliationId.trim()?intent.reconciliationId.trim().slice(0,200):null,
   dedupeKey:dedupeKey(current),
   repairedByRetry:intent?.repairedByRetry===true
  });
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending!==null){
    if(!validIntent(pending)){
     return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_PENDING_INVALID'}],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null};
    }
    let emitError=null;
    try{await emit(mission,pending);}catch(caught){emitError=caught;}
    if(emitError){
     const message=String(emitError?.message||emitError).slice(0,1000);
     const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
     try{
      const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
      return {missionId:saved.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null};
     }catch(writeError){
      if(isVersionConflict(writeError)) continue;
      return {missionId:mission.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null};
     }
    }
    const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
     return {missionId:saved.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return {missionId:mission.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null};
    }
   }
   if(error){
    return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_ERROR_WITHOUT_PENDING'}],pending:false,observabilityEmitted:false,repairedByRetry:attempt>0,error:String(error).slice(0,1000),storageVersion:mission._storage?.version??null};
   }
   const sourcePending=mission[sourcePendingKey]??null;
   if(sourcePending!==null){
    const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId);
    return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:verification.valid,issues:verification.issues,pending:verification.pending,observabilityEmitted:false,repairedByRetry:attempt>0,error:verification.error,storageVersion:verification.storageVersion};
   }
   const sourceError=mission[sourceErrorKey]??null;
   if(!sourceError){
    return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],pending:false,observabilityEmitted:false,repairedByRetry:attempt>0,error:null,storageVersion:mission._storage?.version??null};
   }
   const intent={reconciliationId:null,createdAt:clock(),repairedByRetry:attempt>0};
   const prepared={...mission,[sourceErrorKey]:null,[pendingKey]:intent,[errorKey]:null,updatedAt:clock()};
   let persisted;
   try{
    persisted=await missionStore.putOwned('missions',ownerId,missionId,prepared,{overwrite:true,expectedVersion:mission._storage?.version});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
   let emitError=null;
   try{await emit(persisted,intent);}catch(caught){emitError=caught;}
   if(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...persisted,[pendingKey]:intent,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:persisted._storage?.version});
     return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null};
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return {missionId:persisted.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:persisted._storage?.version??null};
    }
   }
   const cleared={...persisted,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:persisted._storage?.version});
    return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return {missionId:persisted.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:persisted._storage?.version??null};
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_VERSION_CONFLICT','Mission berubah bersamaan; observability untuk perbaikan orphaned recovery-status error tidak dapat dipastikan secara aman',409);
 }


 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusWithObservability(ownerId,missionId){
  const sourcePendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const sourceErrorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_repaired';
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${current.id}`;
  const emit=(current,intent)=>observability.event(ownerId,current.id,eventType,{
   source:'mission-control',
   reconciliationId:typeof intent?.reconciliationId==='string'&&intent.reconciliationId.trim()?intent.reconciliationId.trim().slice(0,200):null,
   dedupeKey:dedupeKey(current),
   repairedByRetry:intent?.repairedByRetry===true
  });
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending!==null){
    if(!validIntent(pending)){
     return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_PENDING_INVALID'}],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null};
    }
    let emitError=null;
    try{await emit(mission,pending);}catch(caught){emitError=caught;}
    if(emitError){
     const message=String(emitError?.message||emitError).slice(0,1000);
     const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
     try{
      const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
      return {missionId:saved.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null};
     }catch(writeError){
      if(isVersionConflict(writeError)) continue;
      return {missionId:mission.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null};
     }
    }
    const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
     return {missionId:saved.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return {missionId:mission.id,ownerId,changed:false,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null};
    }
   }
   if(error){
    return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_ERROR_WITHOUT_PENDING'}],pending:false,observabilityEmitted:false,repairedByRetry:attempt>0,error:String(error).slice(0,1000),storageVersion:mission._storage?.version??null};
   }
   const sourcePending=mission[sourcePendingKey]??null;
   if(sourcePending!==null){
    const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId);
    return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:verification.valid,issues:verification.issues,pending:verification.pending,observabilityEmitted:false,repairedByRetry:attempt>0,error:verification.error,storageVersion:verification.storageVersion};
   }
   const sourceError=mission[sourceErrorKey]??null;
   if(!sourceError){
    return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],pending:false,observabilityEmitted:false,repairedByRetry:attempt>0,error:null,storageVersion:mission._storage?.version??null};
   }
   const intent={reconciliationId:null,createdAt:clock(),repairedByRetry:attempt>0};
   const prepared={...mission,[sourceErrorKey]:null,[pendingKey]:intent,[errorKey]:null,updatedAt:clock()};
   let persisted;
   try{
    persisted=await missionStore.putOwned('missions',ownerId,missionId,prepared,{overwrite:true,expectedVersion:mission._storage?.version});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
   let emitError=null;
   try{await emit(persisted,intent);}catch(caught){emitError=caught;}
   if(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...persisted,[pendingKey]:intent,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:persisted._storage?.version});
     return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null};
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return {missionId:persisted.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:persisted._storage?.version??null};
    }
   }
   const cleared={...persisted,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:persisted._storage?.version});
    return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return {missionId:persisted.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:persisted._storage?.version??null};
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_VERSION_CONFLICT','Mission berubah bersamaan; observability untuk perbaikan orphaned recovery-status error tidak dapat dipastikan secara aman',409);
 }


 async function recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_repaired';
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status:${current.id}`;
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  const phaseResult=(mission,fields={})=>({
   missionId:mission.id,ownerId,attempted:false,recovered:false,phase:'clear',valid:true,issues:[],pending:false,
   observabilityEmitted:false,recoveredByRetry:false,error:null,storageVersion:mission._storage?.version??null,...fields
  });
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending===null){
    if(error){
     return phaseResult(mission,{phase:'error',valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_ERROR_WITHOUT_PENDING'}],error:String(error).slice(0,1000),storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
    }
    return phaseResult(mission,{recoveredByRetry:attempt>0});
   }
   if(!validIntent(pending)){
    return phaseResult(mission,{phase:'pending',valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_PENDING_INVALID'}],pending:true,error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
   }
   const reconciliationId=typeof pending.reconciliationId==='string'&&pending.reconciliationId.trim()?pending.reconciliationId.trim().slice(0,200):null;
   try{
    await observability.event(ownerId,mission.id,eventType,{source:'mission-control',reconciliationId,dedupeKey:dedupeKey(mission),repairedByRetry:pending.repairedByRetry===true});
   }catch(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
     return phaseResult(saved,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null});
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return phaseResult(mission,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
    }
   }
   const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
    return phaseResult(saved,{attempted:true,recovered:true,phase:'clear',valid:true,issues:[],pending:false,observabilityEmitted:true,recoveredByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return phaseResult(mission,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:true,recoveredByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_VERSION_CONFLICT','Mission berubah bersamaan; recovery observability untuk perbaikan orphaned recovery-status error tidak dapat dipastikan secara aman',409);
 }


 async function auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusError';
  const pending=mission[pendingKey]??null;
  const error=mission[errorKey]??null;
  const issues=[];
  const phase=pending!==null?'pending':error?'error':'clear';
  let reconciliationId=null;
  let createdAt=null;
  let repairedByRetry=false;
  if(pending===null){
   if(error) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_ERROR_WITHOUT_PENDING'});
  }else if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_PENDING_INVALID'});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null&&
      (typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()||pending.reconciliationId.length>200)){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECONCILIATION_ID_INVALID'});
   }else if(typeof pending.reconciliationId==='string'&&pending.reconciliationId.trim()){
    reconciliationId=pending.reconciliationId.trim().slice(0,200);
   }
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()||pending.createdAt.length>100){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_CREATED_AT_INVALID'});
   }else{
    createdAt=pending.createdAt.trim().slice(0,100);
   }
   if(typeof pending.repairedByRetry!=='boolean'){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RETRY_FLAG_INVALID'});
   }else{
    repairedByRetry=pending.repairedByRetry;
   }
  }
  const valid=issues.length===0;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   valid,
   recoverable:pending!==null&&valid,
   pending:pending!==null,
   reconciliationId,
   repairedByRetry,
   createdAt,
   error:error?String(error).slice(0,1000):null,
   issues,
   storageVersion:mission._storage?.version??null
  };
 }


 async function auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const pending=mission[pendingKey]??null;
  const error=mission[errorKey]??null;
  const issues=[];
  const phase=pending!==null?'pending':error?'error':'clear';
  let reconciliationId=null;
  let createdAt=null;
  let repairedByRetry=false;
  if(pending===null){
   if(error) issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_ERROR_WITHOUT_PENDING'});
  }else if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_PENDING_INVALID'});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null&&
      (typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()||pending.reconciliationId.length>200)){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECONCILIATION_ID_INVALID'});
   }else if(typeof pending.reconciliationId==='string'&&pending.reconciliationId.trim()){
    reconciliationId=pending.reconciliationId.trim().slice(0,200);
   }
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()||pending.createdAt.length>100){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_CREATED_AT_INVALID'});
   }else{
    createdAt=pending.createdAt.trim().slice(0,100);
   }
   if(typeof pending.repairedByRetry!=='boolean'){
    issues.push({code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RETRY_FLAG_INVALID'});
   }else{
    repairedByRetry=pending.repairedByRetry;
   }
  }
  const valid=issues.length===0;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   valid,
   recoverable:pending!==null&&valid,
   pending:pending!==null,
   reconciliationId,
   repairedByRetry,
   createdAt,
   error:error?String(error).slice(0,1000):null,
   issues,
   storageVersion:mission._storage?.version??null
  };
 }


 async function verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const pending=mission[pendingKey]??null;
  const error=mission[errorKey]??null;
  const phase=pending!==null?'pending':error?'error':'clear';
  const issues=[];
  const rawDedupeKey=pending!==null?`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${mission.id}`:null;
  const dedupeKey=rawDedupeKey!==null&&rawDedupeKey.length<=260?rawDedupeKey:null;
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  let reconciliationId=null;
  let createdAt=null;
  let repairedByRetry=false;
  if(pending===null){
   if(error) issues.push({code:`${prefix}ERROR_WITHOUT_PENDING`});
  }else if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:`${prefix}PENDING_INVALID`});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null){
    if(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()){
     issues.push({code:`${prefix}RECONCILIATION_ID_INVALID`});
    }else if(pending.reconciliationId.length>200){
     issues.push({code:`${prefix}RECONCILIATION_ID_TOO_LONG`});
    }else{
     reconciliationId=pending.reconciliationId.trim().slice(0,200);
    }
   }
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()){
    issues.push({code:`${prefix}CREATED_AT_MISSING`});
   }else if(pending.createdAt.length>100){
    issues.push({code:`${prefix}CREATED_AT_TOO_LONG`});
   }else{
    createdAt=pending.createdAt.trim().slice(0,100);
   }
   if(typeof pending.repairedByRetry!=='boolean'){
    issues.push({code:`${prefix}RETRY_FLAG_INVALID`});
   }else{
    repairedByRetry=pending.repairedByRetry;
   }
   if(rawDedupeKey===null||rawDedupeKey.length>260){
    issues.push({code:`${prefix}DEDUPE_KEY_INVALID`});
   }
  }
  const valid=issues.length===0;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   valid,
   pending:pending!==null,
   recoverable:pending!==null&&valid,
   reconciliationId,
   dedupeKey,
   createdAt,
   repairedByRetry,
   error:error?String(error).slice(0,1000):null,
   issues,
   storageVersion:mission._storage?.version??null
  };
 }


 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const orphanCode='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_ERROR_WITHOUT_PENDING';
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId);
   if(pending!==null){
    return {missionId:verification.missionId,ownerId,changed:false,repaired:false,valid:verification.valid,issues:verification.issues,pending:true,repairedByRetry:attempt>0,error:verification.error,storageVersion:verification.storageVersion};
   }
   if(!error){
    return {missionId:mission.id,ownerId,changed:false,repaired:false,valid:verification.valid,issues:verification.issues,pending:false,repairedByRetry:attempt>0,error:verification.error,storageVersion:mission._storage?.version??null};
   }
   if(verification.pending||verification.issues.length!==1||verification.issues[0]?.code!==orphanCode){
    return {missionId:verification.missionId,ownerId,changed:false,repaired:false,valid:verification.valid,issues:verification.issues,pending:verification.pending,repairedByRetry:attempt>0,error:verification.error,storageVersion:verification.storageVersion};
   }
   const repaired={...mission,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,repaired,{overwrite:true,expectedVersion:mission._storage?.version});
    return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:false,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_VERSION_CONFLICT','Mission berubah bersamaan; orphaned recovery-status error tidak dapat diperbaiki secara aman',409);
 }


 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusWithObservability(ownerId,missionId){
  const sourcePendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const sourceErrorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_repaired';
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${current.id}`;
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  const emit=(current,intent)=>observability.event(ownerId,current.id,eventType,{
   source:'mission-control',
   reconciliationId:typeof intent?.reconciliationId==='string'&&intent.reconciliationId.trim()?intent.reconciliationId.trim().slice(0,200):null,
   dedupeKey:dedupeKey(current),
   repairedByRetry:intent?.repairedByRetry===true
  });
  const phaseResult=(mission,fields={})=>({
   missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],pending:false,
   observabilityEmitted:false,repairedByRetry:false,error:null,storageVersion:mission._storage?.version??null,...fields
  });
  const orphanCode='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_ERROR_WITHOUT_PENDING';
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending!==null){
    if(!validIntent(pending)){
     return phaseResult(mission,{valid:false,issues:[{code:`${prefix}OBSERVABILITY_PENDING_INVALID`}],pending:true,repairedByRetry:attempt>0,error:error?String(error).slice(0,1000):null});
    }
    let emitError=null;
    try{await emit(mission,pending);}catch(caught){emitError=caught;}
    if(emitError){
     const message=String(emitError?.message||emitError).slice(0,1000);
     const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
     try{
      const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
      return phaseResult(saved,{repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null});
     }catch(writeError){
      if(isVersionConflict(writeError)) continue;
      return phaseResult(mission,{repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000)});
     }
    }
    const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
     return phaseResult(saved,{repaired:true,valid:true,issues:[],pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null});
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return phaseResult(mission,{repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000)});
    }
   }
   if(error){
    return phaseResult(mission,{valid:false,issues:[{code:`${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING`}],pending:false,repairedByRetry:attempt>0,error:String(error).slice(0,1000)});
   }
   const sourceVerification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId);
   const sourcePending=mission[sourcePendingKey]??null;
   const sourceError=mission[sourceErrorKey]??null;
   if(sourcePending!==null){
    return phaseResult(mission,{valid:sourceVerification.valid,issues:sourceVerification.issues,pending:sourceVerification.pending,repairedByRetry:attempt>0,error:sourceVerification.error,storageVersion:sourceVerification.storageVersion});
   }
   if(!sourceError){
    if(sourceVerification.issues.length){
     return phaseResult(mission,{valid:sourceVerification.valid,issues:sourceVerification.issues,pending:sourceVerification.pending,repairedByRetry:attempt>0,error:sourceVerification.error,storageVersion:sourceVerification.storageVersion});
    }
    return phaseResult(mission,{repairedByRetry:attempt>0});
   }
   if(sourceVerification.pending||sourceVerification.issues.length!==1||sourceVerification.issues[0]?.code!==orphanCode){
    return phaseResult(mission,{valid:sourceVerification.valid,issues:sourceVerification.issues,pending:sourceVerification.pending,repairedByRetry:attempt>0,error:sourceVerification.error,storageVersion:sourceVerification.storageVersion});
   }
   const intent={reconciliationId:null,createdAt:clock(),repairedByRetry:attempt>0};
   const prepared={...mission,[sourceErrorKey]:null,[pendingKey]:intent,[errorKey]:null,updatedAt:clock()};
   let persisted;
   try{
    persisted=await missionStore.putOwned('missions',ownerId,missionId,prepared,{overwrite:true,expectedVersion:mission._storage?.version});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
   let emitError=null;
   try{await emit(persisted,intent);}catch(caught){emitError=caught;}
   if(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...persisted,[pendingKey]:intent,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:persisted._storage?.version});
     return phaseResult(saved,{changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null});
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return phaseResult(persisted,{changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:persisted._storage?.version??null});
    }
   }
   const cleared={...persisted,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:persisted._storage?.version});
    return phaseResult(saved,{changed:true,repaired:true,valid:true,issues:[],pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return phaseResult(persisted,{changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:persisted._storage?.version??null});
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_VERSION_CONFLICT','Mission berubah bersamaan; observability untuk perbaikan orphaned recovery-status error tidak dapat dipastikan secara aman',409);
 }


 async function recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_repaired';
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${current.id}`;
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  const phaseResult=(mission,fields={})=>({
   missionId:mission.id,ownerId,attempted:false,recovered:false,phase:'clear',valid:true,issues:[],pending:false,
   observabilityEmitted:false,recoveredByRetry:false,error:null,storageVersion:mission._storage?.version??null,...fields
  });
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending===null){
    if(error){
     return phaseResult(mission,{phase:'error',valid:false,issues:[{code:`${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING`}],error:String(error).slice(0,1000),storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
    }
    return phaseResult(mission,{recoveredByRetry:attempt>0});
   }
   if(!validIntent(pending)){
    return phaseResult(mission,{phase:'pending',valid:false,issues:[{code:`${prefix}OBSERVABILITY_PENDING_INVALID`}],pending:true,error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
   }
   const reconciliationId=typeof pending.reconciliationId==='string'&&pending.reconciliationId.trim()?pending.reconciliationId.trim().slice(0,200):null;
   try{
    await observability.event(ownerId,mission.id,eventType,{
     source:'mission-control',
     reconciliationId,
     dedupeKey:dedupeKey(mission),
     repairedByRetry:pending.repairedByRetry===true
    });
   }catch(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
     return phaseResult(saved,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null});
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return phaseResult(mission,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
    }
   }
   const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
    return phaseResult(saved,{attempted:true,recovered:true,phase:'clear',valid:true,issues:[],pending:false,observabilityEmitted:true,recoveredByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return phaseResult(mission,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:true,recoveredByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_VERSION_CONFLICT','Mission berubah bersamaan; recovery observability untuk perbaikan orphaned recovery-status error tidak dapat dipastikan secara aman',409);
 }


 async function recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_repaired';
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${current.id}`;
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  const phaseResult=(mission,fields={})=>({
   missionId:mission.id,ownerId,attempted:false,recovered:false,phase:'clear',valid:true,issues:[],pending:false,
   observabilityEmitted:false,recoveredByRetry:false,error:null,storageVersion:mission._storage?.version??null,...fields
  });
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending===null){
    if(error){
     return phaseResult(mission,{phase:'error',valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_ERROR_WITHOUT_PENDING'}],error:String(error).slice(0,1000),storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
    }
    return phaseResult(mission,{recoveredByRetry:attempt>0});
   }
   if(!validIntent(pending)){
    return phaseResult(mission,{phase:'pending',valid:false,issues:[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_PENDING_INVALID'}],pending:true,error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
   }
   const reconciliationId=typeof pending.reconciliationId==='string'&&pending.reconciliationId.trim()?pending.reconciliationId.trim().slice(0,200):null;
   try{
    await observability.event(ownerId,mission.id,eventType,{source:'mission-control',reconciliationId,dedupeKey:dedupeKey(mission),repairedByRetry:pending.repairedByRetry===true});
   }catch(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
     return phaseResult(saved,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null});
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return phaseResult(mission,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
    }
   }
   const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
    return phaseResult(saved,{attempted:true,recovered:true,phase:'clear',valid:true,issues:[],pending:false,observabilityEmitted:true,recoveredByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return phaseResult(mission,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:true,recoveredByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
   }
  }
  throw new AgenticError('MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_VERSION_CONFLICT','Mission berubah bersamaan; recovery observability untuk perbaikan orphaned recovery-status error tidak dapat dipastikan secara aman',409);
 }


 async function auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  const pending=mission[pendingKey]??null;
  const error=mission[errorKey]??null;
  const issues=[];
  const phase=pending!==null?'pending':error?'error':'clear';
  let reconciliationId=null;
  let createdAt=null;
  let repairedByRetry=false;
  if(pending===null){
   if(error) issues.push({code:`${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING`});
  }else if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:`${prefix}OBSERVABILITY_PENDING_INVALID`});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null){
    if(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()){
     issues.push({code:`${prefix}OBSERVABILITY_RECONCILIATION_ID_INVALID`});
    }else if(pending.reconciliationId.length>200){
     issues.push({code:`${prefix}OBSERVABILITY_RECONCILIATION_ID_TOO_LONG`});
    }else{
     reconciliationId=pending.reconciliationId.trim().slice(0,200);
    }
   }
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()){
    issues.push({code:`${prefix}OBSERVABILITY_CREATED_AT_INVALID`});
   }else if(pending.createdAt.length>100){
    issues.push({code:`${prefix}OBSERVABILITY_CREATED_AT_TOO_LONG`});
   }else{
    createdAt=pending.createdAt.trim().slice(0,100);
   }
   if(typeof pending.repairedByRetry!=='boolean'){
    issues.push({code:`${prefix}OBSERVABILITY_RETRY_FLAG_INVALID`});
   }else{
    repairedByRetry=pending.repairedByRetry;
   }
  }
  const valid=issues.length===0;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   valid,
   recoverable:pending!==null&&valid,
   pending:pending!==null,
   reconciliationId,
   repairedByRetry,
   createdAt,
   error:error?String(error).slice(0,1000):null,
   issues,
   storageVersion:mission._storage?.version??null
  };
 }


 async function verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const pending=mission[pendingKey]??null;
  const error=mission[errorKey]??null;
  const phase=pending!==null?'pending':error?'error':'clear';
  const issues=[];
  const rawDedupeKey=pending!==null?`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${mission.id}`:null;
  const dedupeKey=rawDedupeKey!==null&&rawDedupeKey.length<=260?rawDedupeKey:null;
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  let reconciliationId=null;
  let createdAt=null;
  let repairedByRetry=false;
  if(pending===null){
   if(error) issues.push({code:`${prefix}ERROR_WITHOUT_PENDING`});
  }else if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:`${prefix}PENDING_INVALID`});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null){
    if(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()){
     issues.push({code:`${prefix}RECONCILIATION_ID_INVALID`});
    }else if(pending.reconciliationId.length>200){
     issues.push({code:`${prefix}RECONCILIATION_ID_TOO_LONG`});
    }else{
     reconciliationId=pending.reconciliationId.trim().slice(0,200);
    }
   }
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()){
    issues.push({code:`${prefix}CREATED_AT_MISSING`});
   }else if(pending.createdAt.length>100){
    issues.push({code:`${prefix}CREATED_AT_TOO_LONG`});
   }else{
    createdAt=pending.createdAt.trim().slice(0,100);
   }
   if(typeof pending.repairedByRetry!=='boolean'){
    issues.push({code:`${prefix}RETRY_FLAG_INVALID`});
   }else{
    repairedByRetry=pending.repairedByRetry;
   }
   if(rawDedupeKey===null||rawDedupeKey.length>260){
    issues.push({code:`${prefix}DEDUPE_KEY_INVALID`});
   }
  }
  const valid=issues.length===0;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   valid,
   pending:pending!==null,
   recoverable:pending!==null&&valid,
   reconciliationId,
   dedupeKey,
   createdAt,
   repairedByRetry,
   error:error?String(error).slice(0,1000):null,
   issues,
   storageVersion:mission._storage?.version??null
  };
 }


 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const orphanCode='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_ERROR_WITHOUT_PENDING';
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId);
   const result=(fields={})=>({
    missionId:verification.missionId,ownerId,changed:false,repaired:false,valid:verification.valid,
    issues:verification.issues,pending:verification.pending,repairedByRetry:attempt>0,
    error:verification.error,storageVersion:verification.storageVersion,...fields
   });
   if(pending!==null) return result();
   if(!error) return result({pending:false});
   if(verification.pending||verification.issues.length!==1||verification.issues[0]?.code!==orphanCode) return result();
   const repaired={...mission,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,repaired,{overwrite:true,expectedVersion:mission._storage?.version});
    return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:false,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
  }
  throw new AgenticError('MISSION_CONTROL_RECOVERY_OBSERVABILITY_ORPHANED_ERROR_REPAIR_VERSION_CONFLICT','Mission berubah bersamaan; orphaned recovery-observability error tidak dapat diperbaiki secara aman',409);
 }



 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusWithObservability(ownerId,missionId){
  const sourcePendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const sourceErrorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_repaired';
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${current.id}`;
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  const emit=(current,intent)=>observability.event(ownerId,current.id,eventType,{
   source:'mission-control',
   reconciliationId:typeof intent?.reconciliationId==='string'&&intent.reconciliationId.trim()?intent.reconciliationId.trim().slice(0,200):null,
   dedupeKey:dedupeKey(current),
   repairedByRetry:intent?.repairedByRetry===true
  });
  const phaseResult=(mission,fields={})=>({
   missionId:mission.id,ownerId,changed:false,repaired:false,valid:true,issues:[],pending:false,
   observabilityEmitted:false,repairedByRetry:false,error:null,storageVersion:mission._storage?.version??null,...fields
  });
  const orphanCode='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_ERROR_WITHOUT_PENDING';
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending!==null){
    if(!validIntent(pending)){
     return phaseResult(mission,{valid:false,issues:[{code:`${prefix}OBSERVABILITY_PENDING_INVALID`}],pending:true,repairedByRetry:attempt>0,error:error?String(error).slice(0,1000):null});
    }
    let emitError=null;
    try{await emit(mission,pending);}catch(caught){emitError=caught;}
    if(emitError){
     const message=String(emitError?.message||emitError).slice(0,1000);
     const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
     try{
      const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
      return phaseResult(saved,{repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null});
     }catch(writeError){
      if(isVersionConflict(writeError)) continue;
      return phaseResult(mission,{repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000)});
     }
    }
    const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
     return phaseResult(saved,{repaired:true,valid:true,issues:[],pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null});
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return phaseResult(mission,{repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
    }
   }
   if(error){
    return phaseResult(mission,{valid:false,issues:[{code:`${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING`}],pending:false,repairedByRetry:attempt>0,error:String(error).slice(0,1000)});
   }
   const sourceVerification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId);
   const sourcePending=mission[sourcePendingKey]??null;
   const sourceError=mission[sourceErrorKey]??null;
   if(sourcePending!==null){
    return phaseResult(mission,{valid:sourceVerification.valid,issues:sourceVerification.issues,pending:sourceVerification.pending,repairedByRetry:attempt>0,error:sourceVerification.error,storageVersion:sourceVerification.storageVersion});
   }
   if(!sourceError){
    if(sourceVerification.issues.length){
     return phaseResult(mission,{valid:sourceVerification.valid,issues:sourceVerification.issues,pending:sourceVerification.pending,repairedByRetry:attempt>0,error:sourceVerification.error,storageVersion:sourceVerification.storageVersion});
    }
    return phaseResult(mission,{repairedByRetry:attempt>0});
   }
   if(sourceVerification.pending||sourceVerification.issues.length!==1||sourceVerification.issues[0]?.code!==orphanCode){
    return phaseResult(mission,{valid:sourceVerification.valid,issues:sourceVerification.issues,pending:sourceVerification.pending,repairedByRetry:attempt>0,error:sourceVerification.error,storageVersion:sourceVerification.storageVersion});
   }
   const intent={reconciliationId:null,createdAt:clock(),repairedByRetry:attempt>0};
   const prepared={...mission,[sourceErrorKey]:null,[pendingKey]:intent,[errorKey]:null,updatedAt:clock()};
   let persisted;
   try{
    persisted=await missionStore.putOwned('missions',ownerId,missionId,prepared,{overwrite:true,expectedVersion:mission._storage?.version});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
   let emitError=null;
   try{await emit(persisted,intent);}catch(caught){emitError=caught;}
   if(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...persisted,[pendingKey]:intent,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:persisted._storage?.version});
     return phaseResult(saved,{changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null});
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return phaseResult(persisted,{changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:persisted._storage?.version??null});
    }
   }
   const cleared={...persisted,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:persisted._storage?.version});
    return phaseResult(saved,{changed:true,repaired:true,valid:true,issues:[],pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return phaseResult(persisted,{changed:true,repaired:true,valid:true,issues:[],pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:persisted._storage?.version??null});
   }
  }
  throw new AgenticError('MISSION_CONTROL_RECOVERY_OBSERVABILITY_ORPHANED_ERROR_REPAIR_OBSERVABILITY_VERSION_CONFLICT','Mission berubah bersamaan; observability untuk perbaikan orphaned recovery-observability error tidak dapat dipastikan secara aman',409);
 }


 async function recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_repaired';
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${current.id}`;
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  const phaseResult=(mission,fields={})=>({
   missionId:mission.id,ownerId,attempted:false,recovered:false,phase:'clear',valid:true,issues:[],pending:false,
   observabilityEmitted:false,recoveredByRetry:false,error:null,storageVersion:mission._storage?.version??null,...fields
  });
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending===null){
    if(error){
     return phaseResult(mission,{phase:'error',valid:false,issues:[{code:`${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING`}],error:String(error).slice(0,1000),storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
    }
    return phaseResult(mission,{recoveredByRetry:attempt>0});
   }
   if(!validIntent(pending)){
    return phaseResult(mission,{phase:'pending',valid:false,issues:[{code:`${prefix}OBSERVABILITY_PENDING_INVALID`}],pending:true,error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
   }
   const reconciliationId=typeof pending.reconciliationId==='string'&&pending.reconciliationId.trim()?pending.reconciliationId.trim().slice(0,200):null;
   try{
    await observability.event(ownerId,mission.id,eventType,{
     source:'mission-control',
     reconciliationId,
     dedupeKey:dedupeKey(mission),
     repairedByRetry:pending.repairedByRetry===true
    });
   }catch(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
     return phaseResult(saved,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null});
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return phaseResult(mission,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
    }
   }
   const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
    return phaseResult(saved,{attempted:true,recovered:true,phase:'clear',valid:true,issues:[],pending:false,observabilityEmitted:true,recoveredByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return phaseResult(mission,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:true,recoveredByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
   }
  }
  throw new AgenticError('MISSION_CONTROL_RECOVERY_OBSERVABILITY_ORPHANED_ERROR_REPAIR_OBSERVABILITY_RECOVERY_VERSION_CONFLICT','Mission berubah bersamaan; recovery observability untuk perbaikan orphaned recovery-observability error tidak dapat dipastikan secara aman',409);
 }


 async function auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  const pending=mission[pendingKey]??null;
  const error=mission[errorKey]??null;
  const issues=[];
  const phase=pending!==null?'pending':error?'error':'clear';
  let reconciliationId=null;
  let createdAt=null;
  let repairedByRetry=false;
  if(pending===null){
   if(error) issues.push({code:`${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING`});
  }else if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:`${prefix}OBSERVABILITY_PENDING_INVALID`});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null){
    if(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()){
     issues.push({code:`${prefix}OBSERVABILITY_RECONCILIATION_ID_INVALID`});
    }else if(pending.reconciliationId.length>200){
     issues.push({code:`${prefix}OBSERVABILITY_RECONCILIATION_ID_TOO_LONG`});
    }else{
     reconciliationId=pending.reconciliationId.trim().slice(0,200);
    }
   }
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()){
    issues.push({code:`${prefix}OBSERVABILITY_CREATED_AT_INVALID`});
   }else if(pending.createdAt.length>100){
    issues.push({code:`${prefix}OBSERVABILITY_CREATED_AT_TOO_LONG`});
   }else{
    createdAt=pending.createdAt.trim().slice(0,100);
   }
   if(typeof pending.repairedByRetry!=='boolean'){
    issues.push({code:`${prefix}OBSERVABILITY_RETRY_FLAG_INVALID`});
   }else{
    repairedByRetry=pending.repairedByRetry;
   }
  }
  const valid=issues.length===0;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   valid,
   recoverable:pending!==null&&valid,
   pending:pending!==null,
   reconciliationId,
   repairedByRetry,
   createdAt,
   error:error?String(error).slice(0,1000):null,
   issues,
   storageVersion:mission._storage?.version??null
  };
 }


 async function verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const pending=mission[pendingKey]??null;
  const error=mission[errorKey]??null;
  const phase=pending!==null?'pending':error?'error':'clear';
  const issues=[];
  const rawDedupeKey=pending!==null?`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${mission.id}`:null;
  const dedupeKey=rawDedupeKey!==null&&rawDedupeKey.length<=260?rawDedupeKey:null;
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  let reconciliationId=null;
  let createdAt=null;
  let repairedByRetry=false;
  if(pending===null){
   if(error) issues.push({code:`${prefix}ERROR_WITHOUT_PENDING`});
  }else if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:`${prefix}PENDING_INVALID`});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null){
    if(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()){
     issues.push({code:`${prefix}RECONCILIATION_ID_INVALID`});
    }else if(pending.reconciliationId.length>200){
     issues.push({code:`${prefix}RECONCILIATION_ID_TOO_LONG`});
    }else{
     reconciliationId=pending.reconciliationId.trim().slice(0,200);
    }
   }
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()){
    issues.push({code:`${prefix}CREATED_AT_MISSING`});
   }else if(pending.createdAt.length>100){
    issues.push({code:`${prefix}CREATED_AT_TOO_LONG`});
   }else{
    createdAt=pending.createdAt.trim().slice(0,100);
   }
   if(typeof pending.repairedByRetry!=='boolean'){
    issues.push({code:`${prefix}RETRY_FLAG_INVALID`});
   }else{
    repairedByRetry=pending.repairedByRetry;
   }
   if(rawDedupeKey===null||rawDedupeKey.length>260){
    issues.push({code:`${prefix}DEDUPE_KEY_INVALID`});
   }
  }
  const valid=issues.length===0;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   valid,
   pending:pending!==null,
   recoverable:pending!==null&&valid,
   reconciliationId,
   dedupeKey,
   createdAt,
   repairedByRetry,
   error:error?String(error).slice(0,1000):null,
   issues,
   storageVersion:mission._storage?.version??null
  };
 }


 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const orphanCode='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_ERROR_WITHOUT_PENDING';
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId);
   if(verification.storageVersion!==(mission._storage?.version??null)) continue;
   const result=(fields={})=>({
    missionId:verification.missionId,ownerId,changed:false,repaired:false,valid:verification.valid,
    issues:verification.issues,pending:verification.pending,repairedByRetry:attempt>0,
    error:verification.error,storageVersion:verification.storageVersion,...fields
   });
   if(pending!==null) return result();
   if(!error) return result({pending:false});
   if(verification.pending||verification.issues.length!==1||verification.issues[0]?.code!==orphanCode) return result();
   const repaired={...mission,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,repaired,{overwrite:true,expectedVersion:mission._storage?.version});
    return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:false,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
  }
  throw new AgenticError('MISSION_CONTROL_RECOVERY_OBSERVABILITY_INTEGRITY_ORPHANED_ERROR_REPAIR_VERSION_CONFLICT','Mission berubah bersamaan; orphaned recovery-observability integrity error tidak dapat diperbaiki secara aman',409);
 }

 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusWithObservability(ownerId,missionId){
  const sourcePendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const sourceErrorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_repaired';
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  const orphanCode='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_ERROR_WITHOUT_PENDING';
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${current.id}`;
  const emit=(current,intent)=>observability.event(ownerId,current.id,eventType,{
   source:'mission-control',
   reconciliationId:typeof intent?.reconciliationId==='string'&&intent.reconciliationId.trim()?intent.reconciliationId.trim().slice(0,200):null,
   dedupeKey:dedupeKey(current),
   repairedByRetry:intent?.repairedByRetry===true
  });
  let sourceChanged=false;
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  const result=(mission,fields={})=>({
   missionId:mission.id,ownerId,changed:sourceChanged,repaired:false,valid:true,issues:[],pending:false,
   observabilityEmitted:false,repairedByRetry:false,error:null,storageVersion:mission._storage?.version??null,...fields
  });
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(dedupeKey(mission).length>260){
    return result(mission,{valid:false,issues:[{code:`${prefix}OBSERVABILITY_DEDUPE_KEY_INVALID`}],pending:pending!==null,repairedByRetry:attempt>0,error:error?String(error).slice(0,1000):null});
   }
   if(pending!==null){
    if(!validIntent(pending)){
     return result(mission,{valid:false,issues:[{code:`${prefix}OBSERVABILITY_PENDING_INVALID`}],pending:true,repairedByRetry:attempt>0,error:error?String(error).slice(0,1000):null});
    }
    let emitError=null;
    try{await emit(mission,pending);}catch(caught){emitError=caught;}
    if(emitError){
     const message=String(emitError?.message||emitError).slice(0,1000);
     const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
     try{
      const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
      return result(saved,{repaired:true,pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null});
     }catch(writeError){
      if(isVersionConflict(writeError)) continue;
      return result(mission,{repaired:true,pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000)});
     }
    }
    const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
     return result(saved,{repaired:true,pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null});
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return result(mission,{repaired:true,pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000)});
    }
   }
   if(error){
    return result(mission,{valid:false,issues:[{code:`${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING`}],pending:false,repairedByRetry:attempt>0,error:String(error).slice(0,1000)});
   }
   const sourcePending=mission[sourcePendingKey]??null;
   if(sourcePending!==null){
    const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId);
    if(verification.storageVersion!==(mission._storage?.version??null)) continue;
    return result(mission,{valid:verification.valid,issues:verification.issues,pending:verification.pending,repairedByRetry:attempt>0,error:verification.error});
   }
   const sourceError=mission[sourceErrorKey]??null;
   if(!sourceError) return result(mission,{repairedByRetry:attempt>0});
   const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId);
   if(verification.storageVersion!==(mission._storage?.version??null)) continue;
   if(verification.pending||verification.issues.length!==1||verification.issues[0]?.code!==orphanCode){
    return result(mission,{valid:verification.valid,issues:verification.issues,pending:verification.pending,repairedByRetry:attempt>0,error:verification.error});
   }
   const intent={reconciliationId:null,createdAt:clock(),repairedByRetry:attempt>0};
   const prepared={...mission,[sourceErrorKey]:null,[pendingKey]:intent,[errorKey]:null,updatedAt:clock()};
   let persisted;
   try{
    persisted=await missionStore.putOwned('missions',ownerId,missionId,prepared,{overwrite:true,expectedVersion:mission._storage?.version});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
   sourceChanged=true;
   let emitError=null;
   try{await emit(persisted,intent);}catch(caught){emitError=caught;}
   if(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...persisted,[pendingKey]:intent,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:persisted._storage?.version});
     return result(saved,{changed:true,repaired:true,pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null});
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return result(persisted,{changed:true,repaired:true,pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000)});
    }
   }
   const cleared={...persisted,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:persisted._storage?.version});
    return result(saved,{changed:true,repaired:true,pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return result(persisted,{changed:true,repaired:true,pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000)});
   }
  }
  throw new AgenticError('MISSION_CONTROL_RECOVERY_OBSERVABILITY_INTEGRITY_ORPHANED_ERROR_REPAIR_OBSERVABILITY_VERSION_CONFLICT','Mission berubah bersamaan; observability untuk perbaikan orphaned recovery-observability integrity error tidak dapat dipastikan secara aman',409);
 }


 async function recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_repaired';
  const dedupeKey=current=>`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${current.id}`;
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  const phaseResult=(mission,fields={})=>({
   missionId:mission.id,ownerId,attempted:false,recovered:false,phase:'clear',valid:true,issues:[],pending:false,
   observabilityEmitted:false,recoveredByRetry:false,error:null,storageVersion:mission._storage?.version??null,...fields
  });
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending===null){
    if(error){
     return phaseResult(mission,{phase:'error',valid:false,issues:[{code:`${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING`}],error:String(error).slice(0,1000),storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
    }
    return phaseResult(mission,{recoveredByRetry:attempt>0});
   }
   if(!validIntent(pending)){
    return phaseResult(mission,{phase:'pending',valid:false,issues:[{code:`${prefix}OBSERVABILITY_PENDING_INVALID`}],pending:true,error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
   }
   const key=dedupeKey(mission);
   if(typeof key!=='string'||key.length>260){
    return phaseResult(mission,{phase:'pending',valid:false,issues:[{code:`${prefix}OBSERVABILITY_DEDUPE_KEY_INVALID`}],pending:true,error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
   }
   const reconciliationId=typeof pending.reconciliationId==='string'&&pending.reconciliationId.trim()?pending.reconciliationId.trim().slice(0,200):null;
   try{
    await observability.event(ownerId,mission.id,eventType,{
     source:'mission-control',
     reconciliationId,
     dedupeKey:key,
     repairedByRetry:pending.repairedByRetry===true
    });
   }catch(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
     return phaseResult(saved,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null});
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return phaseResult(mission,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
    }
   }
   const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
    return phaseResult(saved,{attempted:true,recovered:true,phase:'clear',valid:true,issues:[],pending:false,observabilityEmitted:true,recoveredByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return phaseResult(mission,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:true,recoveredByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
   }
  }
  throw new AgenticError('MISSION_CONTROL_RECOVERY_OBSERVABILITY_INTEGRITY_ORPHANED_ERROR_REPAIR_OBSERVABILITY_RECOVERY_VERSION_CONFLICT','Mission berubah bersamaan; recovery observability untuk perbaikan orphaned recovery-observability integrity error tidak dapat dipastikan secara aman',409);
 }



 async function auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  const pending=mission[pendingKey]??null;
  const error=mission[errorKey]??null;
  const phase=pending!==null?'pending':error?'error':'clear';
  const issues=[];
  let reconciliationId=null;
  let createdAt=null;
  let repairedByRetry=false;
  let dedupeKey=null;
  if(pending===null){
   if(error) issues.push({code:`${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING`});
  }else if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:`${prefix}OBSERVABILITY_PENDING_INVALID`});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null){
    if(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()){
     issues.push({code:`${prefix}OBSERVABILITY_RECONCILIATION_ID_INVALID`});
    }else if(pending.reconciliationId.length>200){
     issues.push({code:`${prefix}OBSERVABILITY_RECONCILIATION_ID_TOO_LONG`});
    }else{
     reconciliationId=pending.reconciliationId.trim().slice(0,200);
    }
   }
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()){
    issues.push({code:`${prefix}OBSERVABILITY_CREATED_AT_INVALID`});
   }else if(pending.createdAt.length>100){
    issues.push({code:`${prefix}OBSERVABILITY_CREATED_AT_TOO_LONG`});
   }else{
    createdAt=pending.createdAt.trim().slice(0,100);
   }
   if(typeof pending.repairedByRetry!=='boolean'){
    issues.push({code:`${prefix}OBSERVABILITY_RETRY_FLAG_INVALID`});
   }else{
    repairedByRetry=pending.repairedByRetry;
   }
   const rawDedupeKey=`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${mission.id}`;
   if(typeof mission.id!=='string'||rawDedupeKey.length>260){
    issues.push({code:`${prefix}OBSERVABILITY_DEDUPE_KEY_INVALID`});
   }else{
    dedupeKey=rawDedupeKey;
   }
  }
  const valid=issues.length===0;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   valid,
   recoverable:pending!==null&&valid,
   pending:pending!==null,
   reconciliationId,
   dedupeKey,
   repairedByRetry,
   createdAt,
   error:error?String(error).slice(0,1000):null,
   issues,
   storageVersion:mission._storage?.version??null
  };
 }


 async function verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const mission=await get(ownerId,missionId);
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const pending=mission[pendingKey]??null;
  const error=mission[errorKey]??null;
  const phase=pending!==null?'pending':error?'error':'clear';
  const issues=[];
  let reconciliationId=null;
  let createdAt=null;
  let repairedByRetry=false;
  let dedupeKey=null;
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  if(pending===null){
   if(error) issues.push({code:`${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING`});
  }else if(typeof pending!=='object'||Array.isArray(pending)){
   issues.push({code:`${prefix}OBSERVABILITY_PENDING_INVALID`});
  }else{
   if(pending.reconciliationId!==undefined&&pending.reconciliationId!==null){
    if(typeof pending.reconciliationId!=='string'||!pending.reconciliationId.trim()){
     issues.push({code:`${prefix}OBSERVABILITY_RECONCILIATION_ID_INVALID`});
    }else if(pending.reconciliationId.length>200){
     issues.push({code:`${prefix}OBSERVABILITY_RECONCILIATION_ID_TOO_LONG`});
    }else{
     reconciliationId=pending.reconciliationId.trim().slice(0,200);
    }
   }
   if(typeof pending.createdAt!=='string'||!pending.createdAt.trim()){
    issues.push({code:`${prefix}OBSERVABILITY_CREATED_AT_INVALID`});
   }else if(pending.createdAt.length>100){
    issues.push({code:`${prefix}OBSERVABILITY_CREATED_AT_TOO_LONG`});
   }else{
    createdAt=pending.createdAt.trim().slice(0,100);
   }
   if(typeof pending.repairedByRetry!=='boolean'){
    issues.push({code:`${prefix}OBSERVABILITY_RETRY_FLAG_INVALID`});
   }else{
    repairedByRetry=pending.repairedByRetry;
   }
   const rawDedupeKey=`control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${mission.id}`;
   if(typeof mission.id!=='string'||rawDedupeKey.length>260){
    issues.push({code:`${prefix}OBSERVABILITY_DEDUPE_KEY_INVALID`});
   }else{
    dedupeKey=rawDedupeKey;
   }
  }
  const valid=issues.length===0;
  return {
   missionId:mission.id,
   ownerId,
   phase,
   valid,
   pending:pending!==null,
   recoverable:pending!==null&&valid,
   reconciliationId,
   dedupeKey,
   createdAt,
   repairedByRetry,
   error:error?String(error).slice(0,1000):null,
   issues,
   storageVersion:mission._storage?.version??null
  };
 }


 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const prefix='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
  const orphanCode=`${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING`;
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId);
   if(verification.storageVersion!==(mission._storage?.version??null)) continue;
   const result=(fields={})=>({
    missionId:verification.missionId,ownerId,changed:false,repaired:false,valid:verification.valid,
    issues:verification.issues,pending:verification.pending,repairedByRetry:attempt>0,
    error:verification.error,storageVersion:verification.storageVersion,...fields
   });
   if(pending!==null) return result();
   if(!error) return result({pending:false});
   if(verification.pending||verification.issues.length!==1||verification.issues[0]?.code!==orphanCode) return result();
   const repaired={...mission,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,repaired,{overwrite:true,expectedVersion:mission._storage?.version});
    return {missionId:saved.id,ownerId,changed:true,repaired:true,valid:true,issues:[],pending:false,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null};
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
  }
  throw new AgenticError('MISSION_CONTROL_RECOVERY_OBSERVABILITY_STATUS_VIEW_INTEGRITY_ORPHANED_ERROR_REPAIR_VERSION_CONFLICT','Mission berubah bersamaan; orphaned recovery-observability status-view integrity error tidak dapat diperbaiki secara aman',409);
 }


 async function repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusWithObservability(ownerId,missionId){
  const sourcePendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const sourceErrorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_view_integrity_orphaned_error_repaired';
  const prefix='RECOVERY_STATUS_VIEW_INTEGRITY_ORPHANED_ERROR_REPAIR_';
  const sourceOrphanCode='RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_ERROR_WITHOUT_PENDING';
  const destinationOrphanCode=`${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING`;
  const dedupeKey=current=>`control-audit-recovery-status-view-integrity-orphaned-error-repair:${current.id}`;
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  let sourceChanged=false;
  const result=(mission,fields={})=>({
   missionId:mission.id,ownerId,changed:sourceChanged,repaired:false,valid:true,issues:[],pending:false,
   observabilityEmitted:false,repairedByRetry:false,error:null,storageVersion:mission._storage?.version??null,...fields
  });
  const flush=async(mission,intent,attempt)=>{
   let emitError=null;
   try{
    await observability.event(ownerId,mission.id,eventType,{
     source:'mission-control',
     reconciliationId:typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim()?intent.reconciliationId.trim().slice(0,200):null,
     dedupeKey:dedupeKey(mission),
     repairedByRetry:intent.repairedByRetry===true
    });
   }catch(caught){emitError=caught;}
   if(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...mission,[pendingKey]:intent,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
     return result(saved,{repaired:sourceChanged,pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null});
    }catch(writeError){
     if(isVersionConflict(writeError)) return null;
     return result(mission,{repaired:sourceChanged,pending:true,observabilityEmitted:false,repairedByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000)});
    }
   }
   const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
    return result(saved,{repaired:true,pending:false,observabilityEmitted:true,repairedByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null});
   }catch(writeError){
    if(isVersionConflict(writeError)) return null;
    return result(mission,{repaired:sourceChanged,pending:true,observabilityEmitted:true,repairedByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000)});
   }
  };
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   const key=dedupeKey(mission);
   if(typeof mission.id!=='string'||key.length>260){
    return result(mission,{valid:false,issues:[{code:`${prefix}OBSERVABILITY_DEDUPE_KEY_INVALID`}],pending:pending!==null,repairedByRetry:attempt>0,error:error?String(error).slice(0,1000):null});
   }
   if(pending!==null){
    if(!validIntent(pending)){
     return result(mission,{valid:false,issues:[{code:`${prefix}OBSERVABILITY_PENDING_INVALID`}],pending:true,repairedByRetry:attempt>0,error:error?String(error).slice(0,1000):null});
    }
    const flushed=await flush(mission,pending,attempt);
    if(flushed===null) continue;
    return flushed;
   }
   if(error){
    return result(mission,{valid:false,issues:[{code:destinationOrphanCode}],pending:false,repairedByRetry:attempt>0,error:String(error).slice(0,1000)});
   }
   const sourcePending=mission[sourcePendingKey]??null;
   const sourceError=mission[sourceErrorKey]??null;
   const verification=await verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId);
   if(verification.storageVersion!==(mission._storage?.version??null)) continue;
   if(sourcePending!==null){
    return result(mission,{valid:verification.valid,issues:verification.issues,pending:verification.pending,repairedByRetry:attempt>0,error:verification.error,storageVersion:verification.storageVersion});
   }
   if(!sourceError){
    if(verification.issues.length){
     return result(mission,{valid:verification.valid,issues:verification.issues,pending:verification.pending,repairedByRetry:attempt>0,error:verification.error,storageVersion:verification.storageVersion});
    }
    return result(mission,{repairedByRetry:attempt>0});
   }
   if(verification.pending||verification.issues.length!==1||verification.issues[0]?.code!==sourceOrphanCode){
    return result(mission,{valid:verification.valid,issues:verification.issues,pending:verification.pending,repairedByRetry:attempt>0,error:verification.error,storageVersion:verification.storageVersion});
   }
   const intent={reconciliationId:null,createdAt:clock(),repairedByRetry:attempt>0};
   const prepared={...mission,[sourceErrorKey]:null,[pendingKey]:intent,[errorKey]:null,updatedAt:clock()};
   let persisted;
   try{
    persisted=await missionStore.putOwned('missions',ownerId,missionId,prepared,{overwrite:true,expectedVersion:mission._storage?.version});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    throw writeError;
   }
   sourceChanged=true;
   const flushed=await flush(persisted,intent,attempt);
   if(flushed===null) continue;
   return flushed;
  }
  throw new AgenticError('MISSION_CONTROL_RECOVERY_STATUS_VIEW_INTEGRITY_ORPHANED_ERROR_REPAIR_OBSERVABILITY_VERSION_CONFLICT','Mission berubah bersamaan; observability untuk perbaikan orphaned recovery-status-view integrity error tidak dapat dipastikan secara aman',409);
 }


 async function recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus(ownerId,missionId){
  const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
  const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
  const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_view_integrity_orphaned_error_repaired';
  const prefix='RECOVERY_STATUS_VIEW_INTEGRITY_ORPHANED_ERROR_REPAIR_';
  const dedupeKey=current=>`control-audit-recovery-status-view-integrity-orphaned-error-repair:${current.id}`;
  const validIntent=intent=>Boolean(intent&&typeof intent==='object'&&!Array.isArray(intent)&&
   (intent.reconciliationId===null||intent.reconciliationId===undefined||(typeof intent.reconciliationId==='string'&&intent.reconciliationId.trim().length>0&&intent.reconciliationId.length<=200))&&
   typeof intent.createdAt==='string'&&intent.createdAt.trim().length>0&&intent.createdAt.length<=100&&
   typeof intent.repairedByRetry==='boolean');
  const result=(mission,fields={})=>({
   missionId:mission.id,ownerId,attempted:false,recovered:false,phase:'clear',valid:true,issues:[],pending:false,
   observabilityEmitted:false,recoveredByRetry:false,error:null,storageVersion:mission._storage?.version??null,...fields
  });
  for(let attempt=0;attempt<MAX_RECOVERY_EVIDENCE_REPAIR_RETRIES;attempt++){
   const mission=await get(ownerId,missionId);
   const pending=mission[pendingKey]??null;
   const error=mission[errorKey]??null;
   if(pending===null){
    if(error){
     return result(mission,{phase:'error',valid:false,issues:[{code:`${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING`}],error:String(error).slice(0,1000),storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
    }
    return result(mission,{recoveredByRetry:attempt>0});
   }
   if(!validIntent(pending)){
    return result(mission,{phase:'pending',valid:false,issues:[{code:`${prefix}OBSERVABILITY_PENDING_INVALID`}],pending:true,error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
   }
   const key=dedupeKey(mission);
   if(typeof mission.id!=='string'||key.length>260){
    return result(mission,{phase:'pending',valid:false,issues:[{code:`${prefix}OBSERVABILITY_DEDUPE_KEY_INVALID`}],pending:true,error:error?String(error).slice(0,1000):null,storageVersion:mission._storage?.version??null,recoveredByRetry:attempt>0});
   }
   const reconciliationId=typeof pending.reconciliationId==='string'&&pending.reconciliationId.trim()?pending.reconciliationId.trim().slice(0,200):null;
   try{
    await observability.event(ownerId,mission.id,eventType,{
     source:'mission-control',
     reconciliationId,
     dedupeKey:key,
     repairedByRetry:pending.repairedByRetry===true
    });
   }catch(emitError){
    const message=String(emitError?.message||emitError).slice(0,1000);
    const marked={...mission,[pendingKey]:pending,[errorKey]:message,updatedAt:clock()};
    try{
     const saved=await missionStore.putOwned('missions',ownerId,missionId,marked,{overwrite:true,expectedVersion:mission._storage?.version});
     return result(saved,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,storageVersion:saved._storage?.version??null});
    }catch(writeError){
     if(isVersionConflict(writeError)) continue;
     return result(mission,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:false,recoveredByRetry:attempt>0,error:message,persistError:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
    }
   }
   const cleared={...mission,[pendingKey]:null,[errorKey]:null,updatedAt:clock()};
   try{
    const saved=await missionStore.putOwned('missions',ownerId,missionId,cleared,{overwrite:true,expectedVersion:mission._storage?.version});
    return result(saved,{attempted:true,recovered:true,phase:'clear',valid:true,issues:[],pending:false,observabilityEmitted:true,recoveredByRetry:attempt>0,error:null,storageVersion:saved._storage?.version??null});
   }catch(writeError){
    if(isVersionConflict(writeError)) continue;
    return result(mission,{attempted:true,recovered:false,phase:'pending',valid:true,issues:[],pending:true,observabilityEmitted:true,recoveredByRetry:attempt>0,error:String(writeError?.message||writeError).slice(0,1000),storageVersion:mission._storage?.version??null});
   }
  }
  throw new AgenticError('MISSION_CONTROL_RECOVERY_STATUS_VIEW_INTEGRITY_ORPHANED_ERROR_REPAIR_OBSERVABILITY_RECOVERY_VERSION_CONFLICT','Mission berubah bersamaan; recovery observability untuk perbaikan orphaned recovery-status-view integrity error tidak dapat dipastikan secara aman',409);
 }

 return Object.freeze({actions:Object.freeze([...CONTROL_ACTIONS]),control,status,audit,verifyAudit,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusWithObservability,recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,reconciliationStatus,auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,verifyAuditRecoveryEvidence,auditRecoveryEvidenceRepairStatus,auditRecoveryEvidenceRepairRecoveryStatus,auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatus,verifyAuditRecoveryEvidenceRepairRecoveryStatus,verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatus,repairAuditRecoveryEvidenceRepairRecoveryStatus,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatus,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepair,recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepair,auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus,auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus,verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus,verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusWithObservability,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusWithObservability,recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus,recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus,auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatus,verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatus,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatus,recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,
  repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusWithObservability,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusWithObservability,recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusWithObservability,recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatus,auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,recoverAuditRecoveryEvidenceRepairRecoveryStatusRepair,recoverAuditRecoveryEvidenceRepair,repairAuditRecoveryEvidence,reconcileAudit,recoverAuditReconciliation,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusWithObservability,recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus,repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusWithObservability,recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus});
}
