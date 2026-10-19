import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';

function runtime(initial){
 let current={...initial};
 const events=[];
 const store={
  async getOwned(_scope,ownerId,id){
   if(id!==current.id||ownerId!==current.ownerId)return null;
   return current;
  },
  async putOwned(_scope,_ownerId,_id,next){
   current={...next,_storage:{...(next._storage||{}),version:(current._storage?.version||0)+1}};
   return current;
  },
  current:()=>current
 };
 const observability={
  async event(...args){events.push(args);return {ok:true};},
  async snapshot(_ownerId,mission){return mission;}
 };
 return {store,events,service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-09T00:00:00.000Z'})};
}

const base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:11}};
const pending={reconciliationId:'recon-65',createdAt:'2026-10-09T00:00:00.000Z',repairedByRetry:true};
const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusPending';
const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusError';

test('batch 66 reports clear recovery-status state without mutation or emission',async()=>{
 const r=runtime(base);
 const before=r.store.current();
 const out=await r.service.auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus('u1','m1');
 assert.equal(out.phase,'clear');
 assert.equal(out.valid,true);
 assert.equal(out.pending,false);
 assert.equal(out.recoverable,false);
 assert.equal(out.error,null);
 assert.deepEqual(out.issues,[]);
 assert.strictEqual(r.store.current(),before);
 assert.equal(r.events.length,0);
});

test('batch 66 exposes bounded metadata for a valid pending recovery intent',async()=>{
 const r=runtime({...base,[pendingKey]:pending,[errorKey]:'EVENT_DOWN'});
 const before=r.store.current();
 const out=await r.service.auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus('u1','m1');
 assert.equal(out.phase,'pending');
 assert.equal(out.valid,true);
 assert.equal(out.pending,true);
 assert.equal(out.recoverable,true);
 assert.equal(out.reconciliationId,'recon-65');
 assert.equal(out.createdAt,pending.createdAt);
 assert.equal(out.repairedByRetry,true);
 assert.equal(out.error,'EVENT_DOWN');
 assert.equal(out.storageVersion,11);
 assert.deepEqual(out.issues,[]);
 assert.strictEqual(r.store.current(),before);
 assert.equal(r.events.length,0);
});

test('batch 66 flags a durable error without pending intent as an integrity issue',async()=>{
 const r=runtime({...base,[errorKey]:'ORPHANED_ERROR'});
 const before=r.store.current();
 const out=await r.service.auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus('u1','m1');
 assert.equal(out.phase,'error');
 assert.equal(out.valid,false);
 assert.equal(out.pending,false);
 assert.equal(out.recoverable,false);
 assert.deepEqual(out.issues,[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_ERROR_WITHOUT_PENDING'}]);
 assert.strictEqual(r.store.current(),before);
 assert.equal(r.events.length,0);
});

test('batch 66 fails closed in its status result for malformed pending metadata',async()=>{
 const r=runtime({...base,[pendingKey]:{reconciliationId:'',createdAt:'',repairedByRetry:'yes'},[errorKey]:'EVENT_DOWN'});
 const before=r.store.current();
 const out=await r.service.auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus('u1','m1');
 assert.equal(out.phase,'pending');
 assert.equal(out.valid,false);
 assert.equal(out.recoverable,false);
 assert.equal(out.reconciliationId,null);
 assert.equal(out.createdAt,null);
 assert.equal(out.repairedByRetry,false);
 assert.deepEqual(out.issues.map(x=>x.code),[
  'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECONCILIATION_ID_INVALID',
  'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_CREATED_AT_INVALID',
  'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RETRY_FLAG_INVALID'
 ]);
 assert.strictEqual(r.store.current(),before);
 assert.equal(r.events.length,0);
});

test('batch 66 remains owner-scoped and does not expose another owner mission',async()=>{
 const r=runtime({...base,[pendingKey]:pending});
 await assert.rejects(
  ()=>r.service.auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus('u2','m1'),
  {code:'MISSION_NOT_FOUND'}
 );
 assert.equal(r.events.length,0);
});
