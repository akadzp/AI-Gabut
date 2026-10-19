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

const base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:30}};
const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusPending';
const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusError';
const sourceErrorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError';
const method='recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus';
const eventType='mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_repaired';
const dedupeKey='control-audit-recovery-repair-recovery-status-repair-recovery-status-repair:m1';
const intent={reconciliationId:null,createdAt:'2026-10-09T00:00:00.000Z',repairedByRetry:false};

test('batch 65 recovers a valid pending Batch 64 observability intent and clears durable state',async()=>{
 const r=runtime({...base,[pendingKey]:intent,[errorKey]:'EVENT_DOWN'});
 const out=await r.service[method]('u1','m1');
 assert.equal(out.attempted,true);assert.equal(out.recovered,true);assert.equal(out.phase,'clear');assert.equal(out.valid,true);assert.equal(out.observabilityEmitted,true);assert.equal(out.error,null);
 assert.equal(r.store.current()[pendingKey],null);assert.equal(r.store.current()[errorKey],null);assert.equal(r.store.current()[sourceErrorKey],undefined);
 assert.equal(r.events.length,1);assert.equal(r.events[0][2],eventType);assert.equal(r.events[0][3].dedupeKey,dedupeKey);assert.equal(r.events[0][3].reconciliationId,null);assert.equal(r.events[0][3].repairedByRetry,false);
 assert.equal(out.storageVersion,31);
});

test('batch 65 is a no-op when recovery observability state is clear',async()=>{
 const r=runtime(base);const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.attempted,false);assert.equal(out.recovered,false);assert.equal(out.phase,'clear');assert.equal(out.valid,true);assert.equal(out.observabilityEmitted,false);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 65 persists an emission error while preserving the pending intent',async()=>{
 const r=runtime({...base,[pendingKey]:intent},async()=>{throw new Error('EVENT_DOWN');});
 const out=await r.service[method]('u1','m1');
 assert.equal(out.attempted,true);assert.equal(out.recovered,false);assert.equal(out.phase,'pending');assert.equal(out.valid,true);assert.equal(out.observabilityEmitted,false);assert.equal(out.error,'EVENT_DOWN');
 assert.deepEqual(r.store.current()[pendingKey],intent);assert.equal(r.store.current()[errorKey],'EVENT_DOWN');assert.equal(r.events.length,1);
});

test('batch 65 retries durable pending state with the same deterministic dedupe key',async()=>{
 let fail=true;
 const r=runtime({...base,[pendingKey]:intent,[errorKey]:'EVENT_DOWN'},async()=>{if(fail)throw new Error('EVENT_DOWN');return {ok:true};});
 const first=await r.service[method]('u1','m1');assert.equal(first.recovered,false);assert.equal(first.phase,'pending');
 fail=false;
 const second=await r.service[method]('u1','m1');
 assert.equal(second.recovered,true);assert.equal(second.observabilityEmitted,true);assert.equal(second.phase,'clear');assert.equal(second.recoveredByRetry,false);
 assert.equal(r.store.current()[pendingKey],null);assert.equal(r.store.current()[errorKey],null);assert.equal(r.events.length,2);
 assert.equal(r.events[0][3].dedupeKey,r.events[1][3].dedupeKey);assert.equal(r.events[0][2],r.events[1][2]);
});

test('batch 65 fails closed for malformed pending metadata without mutation or emission',async()=>{
 const r=runtime({...base,[pendingKey]:{reconciliationId:'',createdAt:'2026-10-09T00:00:00.000Z',repairedByRetry:false}});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.attempted,true);assert.equal(out.recovered,false);assert.equal(out.phase,'pending');assert.equal(out.valid,false);assert.equal(out.observabilityEmitted,false);
 assert.deepEqual(out.issues.map(issue=>issue.code),['RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_PENDING_INVALID']);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 65 fails closed for an orphaned durable error without pending intent',async()=>{
 const r=runtime({...base,[errorKey]:'ORPHANED'});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.attempted,false);assert.equal(out.recovered,false);assert.equal(out.phase,'error');assert.equal(out.valid,false);assert.equal(out.observabilityEmitted,false);
 assert.equal(out.issues[0].code,'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_ERROR_WITHOUT_PENDING');
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 65 remains owner-scoped',async()=>{
 const r=runtime({...base,[pendingKey]:intent});
 await assert.rejects(()=>r.service[method]('u2','m1'),error=>error.code==='MISSION_NOT_FOUND');
 assert.equal(r.store.writes(),0);assert.equal(r.events.length,0);
});

test('batch 65 retries an optimistic-concurrency conflict using fresh state and the same dedupe key',async()=>{
 const r=runtime({...base,[pendingKey]:intent},undefined,1);
 const out=await r.service[method]('u1','m1');
 assert.equal(out.recovered,true);assert.equal(out.recoveredByRetry,true);assert.equal(out.observabilityEmitted,true);assert.equal(r.store.current()[pendingKey],null);
 assert.equal(r.events.length,2);assert.equal(r.events[0][3].dedupeKey,r.events[1][3].dedupeKey);assert.equal(r.events[0][2],r.events[1][2]);
});

test('batch 65 stops after bounded repeated version conflicts and preserves pending state',async()=>{
 const r=runtime({...base,[pendingKey]:intent},undefined,2);
 await assert.rejects(()=>r.service[method]('u1','m1'),error=>error.code==='MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_VERSION_CONFLICT'&&error.status===409);
 assert.deepEqual(r.store.current()[pendingKey],intent);assert.equal(r.store.writes(),2);assert.equal(r.events.length,2);
 assert.equal(r.events[0][3].dedupeKey,r.events[1][3].dedupeKey);
});
