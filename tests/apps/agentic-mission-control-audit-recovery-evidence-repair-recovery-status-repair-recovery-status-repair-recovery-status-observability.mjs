import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';

function runtime(initial, emit, conflicts=0){
 let current={...initial};
 let conflictsRemaining=conflicts;
 let writes=0;
 const events=[];
 const store={
  async getOwned(_scope,ownerId,id){if(id!==current.id||ownerId!==current.ownerId)return null;return current;},
  async putOwned(_scope,ownerId,id,next,options={}){
   assert.equal(ownerId,current.ownerId);assert.equal(id,current.id);writes++;
   if(conflictsRemaining>0){conflictsRemaining--;current={...current,_storage:{...(current._storage||{}),version:(current._storage?.version||0)+1}};throw Object.assign(new Error('VERSION_CONFLICT'),{code:'VERSION_CONFLICT'});}
   assert.equal(options.expectedVersion,current._storage?.version);
   current={...next,_storage:{...(next._storage||{}),version:(current._storage?.version||0)+1}};
   return current;
  },
  current:()=>current,
  writes:()=>writes
 };
 const observability={
  async event(...args){events.push(args);if(emit)return emit(...args);return {ok:true};},
  async snapshot(_ownerId,mission){return mission;}
 };
 return {store,service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-09T00:00:00.000Z'}),events};
}

const base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:20}};
const sourcePendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending';
const sourceErrorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError';
const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusPending';
const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusError';
const method='repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusWithObservability';
const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_repaired';
const dedupeKey='control-audit-recovery-repair-recovery-status-repair-recovery-status-repair:m1';

test('batch 64 repairs an orphaned error and emits deterministic durable observability',async()=>{
 const r=runtime({...base,[sourceErrorKey]:'STALE_ERROR'});
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,true);assert.equal(out.repaired,true);assert.equal(out.observabilityEmitted,true);assert.equal(out.pending,false);assert.equal(out.error,null);
 assert.equal(r.store.current()[sourceErrorKey],null);assert.equal(r.store.current()[pendingKey],null);assert.equal(r.store.current()[errorKey],null);
 assert.equal(r.events.length,1);assert.equal(r.events[0][2],eventType);assert.equal(r.events[0][3].dedupeKey,dedupeKey);assert.equal(r.events[0][3].reconciliationId,null);
 assert.equal(out.storageVersion,22);
});

test('batch 64 persists a retryable intent and error when event emission fails',async()=>{
 const r=runtime({...base,[sourceErrorKey]:'STALE_ERROR'},async()=>{throw new Error('EVENT_DOWN');});
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,true);assert.equal(out.repaired,true);assert.equal(out.observabilityEmitted,false);assert.equal(out.pending,true);assert.equal(out.error,'EVENT_DOWN');
 assert.equal(r.store.current()[sourceErrorKey],null);assert.ok(r.store.current()[pendingKey]);assert.equal(r.store.current()[errorKey],'EVENT_DOWN');
 assert.equal(r.events.length,1);assert.equal(r.events[0][2],eventType);assert.equal(r.events[0][3].dedupeKey,dedupeKey);
});

test('batch 64 retries a persisted intent without repeating the canonical repair',async()=>{
 let fail=true;
 const r=runtime({...base,[sourceErrorKey]:'STALE_ERROR'},async()=>{if(fail)throw new Error('EVENT_DOWN');return {ok:true};});
 const first=await r.service[method]('u1','m1');assert.equal(first.observabilityEmitted,false);
 fail=false;
 const second=await r.service[method]('u1','m1');
 assert.equal(second.changed,false);assert.equal(second.repaired,true);assert.equal(second.observabilityEmitted,true);assert.equal(second.pending,false);assert.equal(second.error,null);
 assert.equal(r.store.current()[sourceErrorKey],null);assert.equal(r.store.current()[pendingKey],null);assert.equal(r.store.current()[errorKey],null);
 assert.equal(r.events.length,2);assert.equal(r.events[0][3].dedupeKey,r.events[1][3].dedupeKey);
});

test('batch 64 is a no-op when there is no orphaned error or pending intent',async()=>{
 const r=runtime(base);const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,false);assert.equal(out.repaired,false);assert.equal(out.observabilityEmitted,false);assert.equal(out.pending,false);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 64 preserves an existing source recovery intent without replay or mutation',async()=>{
 const intent={reconciliationId:'recon-62',createdAt:'2026-10-09T00:00:00.000Z',repairedByRetry:true};
 const r=runtime({...base,[sourcePendingKey]:intent,[sourceErrorKey]:'EVENT_DOWN'});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,false);assert.equal(out.repaired,false);assert.equal(out.observabilityEmitted,false);assert.equal(out.pending,true);assert.equal(out.valid,true);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 64 fails closed for malformed source intent',async()=>{
 const r=runtime({...base,[sourcePendingKey]:['malformed'],[sourceErrorKey]:'EVENT_DOWN'});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.valid,false);assert.equal(out.changed,false);assert.equal(out.pending,true);assert.equal(out.observabilityEmitted,false);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 64 fails closed for malformed own pending intent',async()=>{
 const r=runtime({...base,[pendingKey]:['malformed']});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.valid,false);assert.equal(out.pending,true);assert.equal(out.observabilityEmitted,false);
 assert.deepEqual(out.issues.map(issue=>issue.code),['RECOVERY_STATUS_REPAIR_OBSERVABILITY_PENDING_INVALID']);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 64 fails closed for an orphaned observability error marker',async()=>{
 const r=runtime({...base,[errorKey]:'ORPHANED'});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.valid,false);assert.equal(out.pending,false);assert.equal(out.observabilityEmitted,false);
 assert.equal(out.issues[0].code,'RECOVERY_STATUS_REPAIR_OBSERVABILITY_ERROR_WITHOUT_PENDING');
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 64 retries optimistic concurrency conflicts against fresh state',async()=>{
 const r=runtime({...base,[sourceErrorKey]:'STALE_ERROR'},undefined,1);
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,true);assert.equal(out.repaired,true);assert.equal(out.observabilityEmitted,true);assert.equal(out.repairedByRetry,true);
 assert.equal(r.events.length,1);assert.equal(r.events[0][3].repairedByRetry,true);assert.equal(r.store.current()[sourceErrorKey],null);
});

test('batch 64 remains owner-scoped',async()=>{
 const r=runtime({...base,[sourceErrorKey]:'STALE_ERROR'});
 await assert.rejects(()=>r.service[method]('u2','m1'),error=>error.code==='MISSION_NOT_FOUND');
 assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 64 fails closed after bounded repeated version conflicts',async()=>{
 const r=runtime({...base,[sourceErrorKey]:'STALE_ERROR'},undefined,2);
 await assert.rejects(()=>r.service[method]('u1','m1'),error=>error.code==='MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_OBSERVABILITY_VERSION_CONFLICT'&&error.status===409);
 assert.equal(r.store.current()[sourceErrorKey],'STALE_ERROR');assert.equal(r.events.length,0);assert.equal(r.store.writes(),2);
});
