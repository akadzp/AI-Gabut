import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';

function runtime(initial,conflicts=0){
 let current={...initial};
 let conflictsRemaining=conflicts;
 let writes=0;
 let events=0;
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
 const observability={async event(){events++;throw new Error('EVENT_NOT_EXPECTED');},async snapshot(_ownerId,mission){return mission;},events:()=>events};
 return {store,service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-09T00:00:00.000Z'}),observability};
}

const base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:15}};
const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending';
const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError';
const method='repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus';
const conflictCode='MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_VERSION_CONFLICT';

test('batch 63 repairs only an orphaned durable recovery-status error',async()=>{
 const r=runtime({...base,[errorKey]:'EVENT_DOWN'});
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,true);assert.equal(out.repaired,true);assert.equal(out.valid,true);assert.equal(out.pending,false);assert.equal(out.error,null);
 assert.equal(r.store.current()[errorKey],null);assert.equal(out.storageVersion,16);assert.equal(r.store.writes(),1);assert.equal(r.observability.events(),0);
});

test('batch 63 preserves pending intent and its error without replay or mutation',async()=>{
 const intent={reconciliationId:'recon-62',repairedByRetry:true,createdAt:'2026-10-09T00:00:00.000Z'};
 const r=runtime({...base,[pendingKey]:intent,[errorKey]:'EVENT_DOWN'});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,false);assert.equal(out.repaired,false);assert.equal(out.valid,true);assert.equal(out.pending,true);assert.equal(out.error,'EVENT_DOWN');
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.observability.events(),0);
});

test('batch 63 fails closed on malformed pending state and does not clear its error',async()=>{
 const r=runtime({...base,[pendingKey]:['malformed'],[errorKey]:'EVENT_DOWN'});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,false);assert.equal(out.repaired,false);assert.equal(out.valid,false);assert.equal(out.pending,true);
 assert.deepEqual(out.issues.map(issue=>issue.code),['RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_PENDING_INVALID']);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.observability.events(),0);
});

test('batch 63 is a read-only no-op when recovery-status state is clear',async()=>{
 const r=runtime(base);const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,false);assert.equal(out.repaired,false);assert.equal(out.valid,true);assert.equal(out.pending,false);assert.equal(out.error,null);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);
});

test('batch 63 retries an optimistic-concurrency conflict against the latest mission version',async()=>{
 const r=runtime({...base,[errorKey]:'EVENT_DOWN'},1);
 const out=await r.service[method]('u1','m1');
 assert.equal(out.changed,true);assert.equal(out.repaired,true);assert.equal(out.repairedByRetry,true);assert.equal(r.store.current()[errorKey],null);
 assert.equal(r.store.writes(),2);assert.equal(out.storageVersion,17);
});

test('batch 63 fails closed after bounded repeated version conflicts',async()=>{
 const r=runtime({...base,[errorKey]:'EVENT_DOWN'},2);
 await assert.rejects(()=>r.service[method]('u1','m1'),error=>error.code===conflictCode&&error.status===409);
 assert.equal(r.store.current()[errorKey],'EVENT_DOWN');assert.equal(r.store.writes(),2);
});

test('batch 63 remains owner-scoped',async()=>{
 const r=runtime({...base,[errorKey]:'EVENT_DOWN'});
 await assert.rejects(()=>r.service[method]('u2','m1'),error=>error.code==='MISSION_NOT_FOUND');
 assert.equal(r.store.writes(),0);
});
