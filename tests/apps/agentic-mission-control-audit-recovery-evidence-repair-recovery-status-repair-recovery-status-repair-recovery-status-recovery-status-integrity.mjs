import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';

function runtime(initial){
 let current={...initial};
 let writes=0;
 let emissions=0;
 const store={
  async getOwned(_scope,ownerId,id){if(id!==current.id||ownerId!==current.ownerId)return null;return current;},
  async putOwned(){writes++;throw new Error('MUTATION_NOT_EXPECTED');},
  current:()=>current,
  writes:()=>writes
 };
 const observability={async event(){emissions++;throw new Error('EVENT_NOT_EXPECTED');},async snapshot(_ownerId,mission){return mission;}};
 return {store,service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-09T00:00:00.000Z'}),emissions:()=>emissions};
}

const base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:22}};
const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusPending';
const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusError';
const method='verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatus';
const dedupeKey='control-audit-recovery-repair-recovery-status-repair-recovery-status-repair:m1';
const intent={reconciliationId:'recon-66',createdAt:'2026-10-09T00:00:00.000Z',repairedByRetry:true};

test('batch 67 verifies clear recovery-status state without mutation or emission',async()=>{
 const r=runtime(base);const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.phase,'clear');assert.equal(out.valid,true);assert.equal(out.pending,false);assert.equal(out.recoverable,false);
 assert.equal(out.dedupeKey,null);assert.equal(out.error,null);assert.deepEqual(out.issues,[]);assert.equal(out.storageVersion,22);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.emissions(),0);
});

test('batch 67 verifies valid pending metadata and deterministic mission-scoped dedupe key',async()=>{
 const r=runtime({...base,[pendingKey]:intent,[errorKey]:'EVENT_DOWN'});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.phase,'pending');assert.equal(out.valid,true);assert.equal(out.pending,true);assert.equal(out.recoverable,true);
 assert.equal(out.reconciliationId,'recon-66');assert.equal(out.createdAt,intent.createdAt);assert.equal(out.repairedByRetry,true);
 assert.equal(out.dedupeKey,dedupeKey);assert.equal(out.error,'EVENT_DOWN');assert.deepEqual(out.issues,[]);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.emissions(),0);
});

test('batch 67 accepts canonical nullable reconciliation IDs',async()=>{
 const r=runtime({...base,[pendingKey]:{reconciliationId:null,createdAt:intent.createdAt,repairedByRetry:false}});
 const out=await r.service[method]('u1','m1');
 assert.equal(out.valid,true);assert.equal(out.reconciliationId,null);assert.equal(out.repairedByRetry,false);assert.equal(out.dedupeKey,dedupeKey);assert.deepEqual(out.issues,[]);
});

test('batch 67 detects malformed pending object and field types with stable issue codes',async()=>{
 const r=runtime({...base,[pendingKey]:{reconciliationId:'',createdAt:'',repairedByRetry:'yes'}});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.valid,false);assert.equal(out.recoverable,false);
 assert.deepEqual(out.issues.map(x=>x.code),[
  'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECONCILIATION_ID_INVALID',
  'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_CREATED_AT_MISSING',
  'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RETRY_FLAG_INVALID'
 ]);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.emissions(),0);
});

test('batch 67 detects oversized pending metadata and bounds returned fields',async()=>{
 const r=runtime({...base,[pendingKey]:{reconciliationId:'r'.repeat(201),createdAt:'t'.repeat(101),repairedByRetry:false},[errorKey]:'e'.repeat(1100)});
 const out=await r.service[method]('u1','m1');
 assert.equal(out.valid,false);assert.equal(out.reconciliationId,null);assert.equal(out.createdAt,null);assert.equal(out.error.length,1000);
 assert.deepEqual(out.issues.map(x=>x.code),[
  'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECONCILIATION_ID_TOO_LONG',
  'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_CREATED_AT_TOO_LONG'
 ]);
 assert.equal(out.dedupeKey,dedupeKey);
});

test('batch 67 reports orphaned durable error as invalid and does not mutate state',async()=>{
 const r=runtime({...base,[errorKey]:'ORPHANED_ERROR'});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.phase,'error');assert.equal(out.valid,false);assert.equal(out.pending,false);assert.equal(out.recoverable,false);assert.equal(out.dedupeKey,null);
 assert.deepEqual(out.issues,[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_ERROR_WITHOUT_PENDING'}]);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.emissions(),0);
});

test('batch 67 rejects non-object pending intent without mutation or emission',async()=>{
 const r=runtime({...base,[pendingKey]:['invalid']});const before=r.store.current();
 const out=await r.service[method]('u1','m1');
 assert.equal(out.valid,false);assert.equal(out.pending,true);assert.equal(out.recoverable,false);
 assert.deepEqual(out.issues,[{code:'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_PENDING_INVALID'}]);
 assert.strictEqual(r.store.current(),before);assert.equal(r.store.writes(),0);assert.equal(r.emissions(),0);
});

test('batch 67 remains owner-scoped',async()=>{
 const r=runtime({...base,[pendingKey]:intent});
 await assert.rejects(()=>r.service[method]('u2','m1'),error=>error.code==='MISSION_NOT_FOUND');
 assert.equal(r.store.writes(),0);assert.equal(r.emissions(),0);
});
