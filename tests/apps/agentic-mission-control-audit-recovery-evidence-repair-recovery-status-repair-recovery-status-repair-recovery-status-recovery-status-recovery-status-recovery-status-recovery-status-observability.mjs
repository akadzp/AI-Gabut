import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';

function runtime(initial,{emit=null,conflictWrites=[]}={}){
 let current={...initial};
 const events=[];
 const conflictSet=new Set(conflictWrites);
 let writes=0;
 const store={
  async getOwned(_scope,ownerId,id){if(id!==current.id||ownerId!==current.ownerId)return null;return current;},
  async putOwned(_scope,ownerId,id,next,options={}){
   assert.equal(ownerId,current.ownerId);assert.equal(id,current.id);writes++;
   if(conflictSet.has(writes)){
    current={...current,_storage:{...(current._storage||{}),version:(current._storage?.version||0)+1}};
    throw Object.assign(new Error('VERSION_CONFLICT'),{code:'VERSION_CONFLICT'});
   }
   assert.equal(options.expectedVersion,current._storage?.version);
   current={...next,_storage:{...(next._storage||{}),version:(current._storage?.version||0)+1}};
   return current;
  },
  current:()=>current,
  writes:()=>writes
 };
 const observability={
  async event(...args){events.push(args);return emit?emit(args,events.length):{ok:true};},
  async snapshot(_ownerId,mission){return mission;}
 };
 return {store,service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-10T00:00:00.000Z'}),events};
}

const base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:78}};
const sourcePendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
const sourceErrorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
const method='repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusWithObservability';
const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_repaired';
const dedupeKey='control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:m1';
const conflictCode='MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_VERSION_CONFLICT';
const intent={reconciliationId:null,createdAt:'2026-10-10T00:00:00.000Z',repairedByRetry:false};

test('batch 79 atomically clears the orphaned source error and emits deterministic repair evidence',async()=>{
 const r=runtime({...base,[sourceErrorKey]:'ORPHANED_ERROR'});
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,true);assert.equal(out.repaired,true);assert.equal(out.valid,true);assert.equal(out.pending,false);assert.equal(out.observabilityEmitted,true);
 assert.equal(r.store.current()[sourceErrorKey],null);assert.equal(r.store.current()[pendingKey],null);assert.equal(r.store.current()[errorKey],null);
 assert.equal(r.events.length,1);assert.equal(r.events[0][2],eventType);assert.equal(r.events[0][3].dedupeKey,dedupeKey);assert.equal(r.events[0][3].reconciliationId,null);
 assert.equal(r.store.writes(),2);assert.equal(out.storageVersion,80);
});

test('batch 79 persists a retryable intent when event emission fails',async()=>{
 const r=runtime({...base,[sourceErrorKey]:'ORPHANED_ERROR'},{emit:async()=>{throw new Error('EVENT_DOWN');}});
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,true);assert.equal(out.repaired,true);assert.equal(out.pending,true);assert.equal(out.observabilityEmitted,false);assert.equal(out.error,'EVENT_DOWN');
 assert.equal(r.store.current()[sourceErrorKey],null);assert.deepEqual(r.store.current()[pendingKey],intent);assert.equal(r.store.current()[errorKey],'EVENT_DOWN');
 assert.equal(r.events.length,1);assert.equal(r.store.writes(),2);
});

test('batch 79 retries a durable pending intent without replaying the source repair',async()=>{
 let shouldFail=true;
 const r=runtime({...base,[sourceErrorKey]:'ORPHANED_ERROR'},{emit:async()=>{if(shouldFail){shouldFail=false;throw new Error('EVENT_DOWN');}}});
 const first=await r.service[method]('u1','m1');assert.equal(first.pending,true);assert.equal(r.store.current()[sourceErrorKey],null);
 const second=await r.service[method]('u1','m1');
 assert.equal(second.changed,false);assert.equal(second.repaired,true);assert.equal(second.pending,false);assert.equal(second.observabilityEmitted,true);
 assert.equal(r.events.length,2);assert.equal(r.events[0][3].dedupeKey,r.events[1][3].dedupeKey);assert.equal(r.events[1][2],eventType);
 assert.equal(r.store.current()[pendingKey],null);assert.equal(r.store.current()[errorKey],null);
});

test('batch 79 fails closed on malformed destination intent',async()=>{
 const malformed=['bad-intent'];const r=runtime({...base,[pendingKey]:malformed,[errorKey]:'EVENT_DOWN'});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,false);assert.equal(out.repaired,false);assert.equal(out.valid,false);assert.equal(out.pending,true);
 assert.deepEqual(out.issues.map(issue=>issue.code),['RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_PENDING_INVALID']);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 79 fails closed on an orphaned destination error marker',async()=>{
 const r=runtime({...base,[errorKey]:'ORPHANED_DESTINATION_ERROR'});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,false);assert.equal(out.repaired,false);assert.equal(out.valid,false);assert.equal(out.pending,false);
 assert.deepEqual(out.issues.map(issue=>issue.code),['RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_ERROR_WITHOUT_PENDING']);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 79 preserves source pending intent and its error without mutation or emission',async()=>{
 const sourceIntent={reconciliationId:'recon-73',createdAt:'2026-10-10T00:00:00.000Z',repairedByRetry:false};
 const r=runtime({...base,[sourcePendingKey]:sourceIntent,[sourceErrorKey]:'SOURCE_EVENT_DOWN'});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,false);assert.equal(out.repaired,false);assert.equal(out.valid,true);assert.equal(out.pending,true);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 79 fails closed and preserves malformed source pending intent',async()=>{
 const r=runtime({...base,[sourcePendingKey]:['malformed'],[sourceErrorKey]:'SOURCE_EVENT_DOWN'});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,false);assert.equal(out.repaired,false);assert.equal(out.valid,false);assert.equal(out.pending,true);
 assert.deepEqual(out.issues.map(issue=>issue.code),['RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_PENDING_INVALID']);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 79 is a read-only no-op when neither source nor destination state needs repair',async()=>{
 const r=runtime(base);const before=r.store.current();const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,false);assert.equal(out.repaired,false);assert.equal(out.valid,true);assert.equal(out.pending,false);assert.equal(out.observabilityEmitted,false);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 79 retries optimistic-concurrency conflict against the latest source state',async()=>{
 const r=runtime({...base,[sourceErrorKey]:'ORPHANED_ERROR'},{conflictWrites:[1]});
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,true);assert.equal(out.repaired,true);assert.equal(out.repairedByRetry,true);assert.equal(out.observabilityEmitted,true);
 assert.equal(r.store.current()[sourceErrorKey],null);assert.equal(r.store.current()[pendingKey],null);assert.equal(r.store.writes(),3);assert.equal(r.events.length,1);
});

test('batch 79 fails closed after bounded repeated version conflicts',async()=>{
 const r=runtime({...base,[sourceErrorKey]:'ORPHANED_ERROR'},{conflictWrites:[1,2]});
 await assert.rejects(()=>r.service[method]('u1','m1'),error=>error.code===conflictCode&&error.status===409);
 assert.equal(r.store.current()[sourceErrorKey],'ORPHANED_ERROR');assert.equal(r.store.writes(),2);assert.equal(r.events.length,0);
});

test('batch 79 reuses deterministic deduplication after finalization conflict',async()=>{
 const r=runtime({...base,[sourceErrorKey]:'ORPHANED_ERROR'},{conflictWrites:[2]});
 const out=await r.service[method]('u1','m1');
 assert.equal(out.repaired,true);assert.equal(out.pending,false);assert.equal(out.observabilityEmitted,true);
 assert.equal(r.events.length,2);assert.equal(r.events[0][3].dedupeKey,dedupeKey);assert.equal(r.events[1][3].dedupeKey,dedupeKey);
 assert.equal(r.store.current()[pendingKey],null);assert.equal(r.store.current()[errorKey],null);
});

test('batch 79 remains owner-scoped',async()=>{
 const r=runtime({...base,[sourceErrorKey]:'ORPHANED_ERROR'});
 await assert.rejects(()=>r.service[method]('u2','m1'),error=>error.code==='MISSION_NOT_FOUND');
 assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});
