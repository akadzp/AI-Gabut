const createId=prefix=>`${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2,10)}`;
class AgenticError extends Error { constructor(code,message,status=400){super(message);this.code=code;this.status=status;} }
const STATUSES=new Set(['queued','running','paused','waiting_approval','failed','completed','cancelled']);
const EVENTS=new Set(['stage_started','stage_completed','stage_failed','stage_paused','stage_resumed','approval_requested','approval_resolved','checkpoint_saved','mission_completed','mission_recovered','mission_cancelled','mission_control_audit_reconciled']);
const clean=(v,n=4000)=>String(v??'').trim().slice(0,n);
const dedupePart=v=>clean(v,180).replace(/[^a-zA-Z0-9._:-]/g,'_');

export function createMissionObservability({store,realtime=null,clock=()=>new Date().toISOString()}={}){
 if(!store) throw new Error('Mission observability membutuhkan store');
 async function event(ownerId,missionId,type,payload={}){
  if(!EVENTS.has(type)) throw new AgenticError('INVALID_MISSION_EVENT','Jenis mission event tidak valid');
  const input={...payload};
  const dedupeKey=clean(input.dedupeKey,300)||null;
  delete input.dedupeKey;
  const existing=dedupeKey?((await listEvents(ownerId,missionId)).find(x=>x.dedupeKey===dedupeKey)||null):null;
  if(existing) return existing;
  const createdAt=clock();
  const events=await listEvents(ownerId,missionId);
  const sequence=(events.reduce((max,x)=>Math.max(max,Number(x.sequence)||0),0)||0)+1;
  const item={id:dedupeKey?`mission-event-${dedupePart(ownerId)}-${dedupePart(missionId)}-${dedupePart(dedupeKey)}`:createId('mission-event'),missionId,ownerId,type,dedupeKey,sequence,payload:input,createdAt};
  try {
   await store.putOwned('mission-events',ownerId,item.id,item,{overwrite:false});
  } catch(error) {
   if(dedupeKey){const raced=(await listEvents(ownerId,missionId)).find(x=>x.dedupeKey===dedupeKey);if(raced)return raced;}
   throw error;
  }
  if(realtime) await realtime.publish(ownerId,{id:createId('activity'),missionId,type:'mission_observability',action:type,status:'completed',label:`Mission · ${type}`,meta:{eventId:item.id,dedupeKey,sequence},createdAt:item.createdAt});
  return item;
 }
 async function listEvents(ownerId,missionId){return (await store.listOwned('mission-events',ownerId)).filter(x=>x.missionId===missionId).sort((a,b)=>{const sa=Number(a.sequence)||0,sb=Number(b.sequence)||0;return sa-sb||String(a.createdAt).localeCompare(String(b.createdAt))||String(a.id).localeCompare(String(b.id));})}
 async function snapshot(ownerId,mission){
  if(!mission?.id) throw new AgenticError('INVALID_MISSION','Mission wajib memiliki id');
  if(mission.ownerId&&mission.ownerId!==ownerId) throw new AgenticError('FORBIDDEN','Mission bukan milik owner');
  const status=STATUSES.has(mission.status)?mission.status:'queued';
  const events=await listEvents(ownerId,mission.id);
  const latest=events.at(-1)||null;
  return {missionId:mission.id,ownerId,status,currentStage:mission.currentStage??null,nextStage:mission.nextStage??null,startedAt:mission.startedAt??null,updatedAt:mission.updatedAt??clock(),latestEvent:latest?.type??null,eventCount:events.length,checkpointId:mission.checkpointId??null,approvalRequired:mission.approvalRequired===true||mission.status==="waiting_approval"||mission.approval?.required===true};
 }
 async function timeline(ownerId,missionId){return listEvents(ownerId,missionId)}
 async function inspect(ownerId,missionId){
  const events=await listEvents(ownerId,missionId);
  const issues=[]; const seenIds=new Set(); const seenDedupe=new Set(); const seenSequences=new Set();
  for(const item of events){
   if(!item?.id) issues.push({code:'MISSING_EVENT_ID',eventId:null});
   else if(seenIds.has(item.id)) issues.push({code:'DUPLICATE_EVENT_ID',eventId:item.id});
   else seenIds.add(item.id);
   if(item?.ownerId!==ownerId) issues.push({code:'OWNER_MISMATCH',eventId:item?.id||null});
   if(item?.missionId!==missionId) issues.push({code:'MISSION_MISMATCH',eventId:item?.id||null});
   if(!EVENTS.has(item?.type)) issues.push({code:'INVALID_EVENT_TYPE',eventId:item?.id||null});
   if(item?.dedupeKey){if(seenDedupe.has(item.dedupeKey))issues.push({code:'DUPLICATE_DEDUPE_KEY',eventId:item.id,dedupeKey:item.dedupeKey});else seenDedupe.add(item.dedupeKey)}
   const seq=Number(item?.sequence); if(!Number.isInteger(seq)||seq<1) issues.push({code:'INVALID_SEQUENCE',eventId:item?.id||null}); else if(seenSequences.has(seq)) issues.push({code:'DUPLICATE_SEQUENCE',eventId:item.id,sequence:seq}); else seenSequences.add(seq);
  }
  const expected=events.map((_,i)=>i+1); const actual=events.map(x=>Number(x.sequence));
  if(actual.length&&actual.some((x,i)=>x!==expected[i])) issues.push({code:'NON_CONTIGUOUS_SEQUENCE'});
  return {missionId,ownerId,healthy:issues.length===0,eventCount:events.length,issues};
 }
 async function repair(ownerId,missionId){
  const events=await listEvents(ownerId,missionId); const report=await inspect(ownerId,missionId);
  if(report.healthy) return {repaired:false,report,events};
  const dedupe=new Set(); const kept=[];
  for(const item of events){
   if(!item||item.ownerId!==ownerId||item.missionId!==missionId||!EVENTS.has(item.type)) continue;
   if(item.dedupeKey&&dedupe.has(item.dedupeKey)) continue;
   if(item.dedupeKey) dedupe.add(item.dedupeKey); kept.push(item);
  }
  kept.sort((a,b)=>String(a.createdAt).localeCompare(String(b.createdAt))||String(a.id).localeCompare(String(b.id)));
  const keepIds=new Set(kept.map(x=>x.id));
  for(const item of events){ if(item?.id&&!keepIds.has(item.id)) await store.removeOwned?.('mission-events',ownerId,item.id); }
  const repaired=[];
  for(let i=0;i<kept.length;i++){
   const item={...kept[i],sequence:i+1};
   await store.putOwned('mission-events',ownerId,item.id,item,{overwrite:true}); repaired.push(item);
  }
  return {repaired:true,report,events:repaired};
 }
 return Object.freeze({statuses:Object.freeze([...STATUSES]),eventTypes:Object.freeze([...EVENTS]),event,timeline,listEvents,snapshot,inspect,repair});
}
