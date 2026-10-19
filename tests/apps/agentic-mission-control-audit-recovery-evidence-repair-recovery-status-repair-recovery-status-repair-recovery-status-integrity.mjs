import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';

function runtime(initial){
 let current={...initial};
 const store={
  async getOwned(_scope,ownerId,id){if(id!==current.id||ownerId!==current.ownerId)return null;return current;},
  async putOwned(){throw new Error('MUTATION_NOT_EXPECTED');},
  current:()=>current
 };
 const observability={async event(){throw new Error('EVENT_NOT_EXPECTED');},async snapshot(_ownerId,mission){return mission;}};
 return {store,service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-09T00:00:00.000Z'})};
}

const base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:15}};
const pending={reconciliationId:'recon-60',createdAt:'2026-10-09T00:00:00.000Z',repairedByRetry:true};
const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending';
const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError';
const dedupeKey='control-audit-recovery-repair-recovery-status-repair:m1';

test('batch 62 verifies a valid pending status-repair recovery intent without mutation or emission',async()=>{
 const r=runtime({...base,[pendingKey]:pending,[errorKey]:'EVENT_DOWN'});const before=r.store.current();
 const out=await r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.valid,true);assert.equal(out.pending,true);assert.equal(out.reconciliationId,'recon-60');
 assert.equal(out.repairedByRetry,true);assert.equal(out.createdAt,pending.createdAt);assert.equal(out.dedupeKey,dedupeKey);assert.deepEqual(out.issues,[]);
 assert.equal(out.error,'EVENT_DOWN');assert.equal(out.storageVersion,15);assert.strictEqual(r.store.current(),before);
});

test('batch 62 accepts the canonical nullable reconciliation ID produced by Batch 59',async()=>{
 const r=runtime({...base,[pendingKey]:{reconciliationId:null,repairedByRetry:false,createdAt:'2026-10-09T00:00:00.000Z'}});
 const out=await r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.valid,true);assert.equal(out.pending,true);assert.equal(out.reconciliationId,null);assert.equal(out.dedupeKey,dedupeKey);assert.deepEqual(out.issues,[]);
});

test('batch 62 detects malformed pending metadata and reports stable issue codes',async()=>{
 const r=runtime({...base,[pendingKey]:{reconciliationId:7,repairedByRetry:'yes',createdAt:''}});
 const out=await r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.valid,false);
 assert.deepEqual(out.issues.map(x=>x.code),[
  'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECONCILIATION_ID_INVALID',
  'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RETRY_FLAG_INVALID',
  'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_CREATED_AT_MISSING'
 ]);
});

test('batch 62 fails closed for orphaned durable error without pending intent',async()=>{
 const r=runtime({...base,[errorKey]:'EVENT_DOWN'});const before=r.store.current();
 const out=await r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.valid,false);assert.equal(out.pending,false);assert.equal(out.dedupeKey,null);
 assert.equal(out.issues[0].code,'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_ERROR_WITHOUT_PENDING');
 assert.equal(out.error,'EVENT_DOWN');assert.strictEqual(r.store.current(),before);
});

test('batch 62 treats clear state as valid and remains owner-scoped',async()=>{
 const r=runtime(base);
 const out=await r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.valid,true);assert.equal(out.pending,false);assert.deepEqual(out.issues,[]);
 await assert.rejects(()=>r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus('u2','m1'),e=>e.code==='MISSION_NOT_FOUND');
});

test('batch 62 rejects a non-object pending intent without mutation',async()=>{
 const r=runtime({...base,[pendingKey]:['invalid']});const before=r.store.current();
 const out=await r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.valid,false);assert.equal(out.pending,true);
 assert.deepEqual(out.issues.map(x=>x.code),['RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_PENDING_INVALID']);
 assert.strictEqual(r.store.current(),before);
});

test('batch 62 bounds returned metadata for oversized fields',async()=>{
 const r=runtime({...base,[pendingKey]:{reconciliationId:'r'.repeat(250),repairedByRetry:false,createdAt:'t'.repeat(130)},[errorKey]:'e'.repeat(1100)});
 const out=await r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.reconciliationId.length,200);assert.equal(out.createdAt.length,100);assert.equal(out.error.length,1000);
 assert.equal(out.dedupeKey,dedupeKey);assert.equal(out.valid,false);
 assert.deepEqual(out.issues.map(x=>x.code),['RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECONCILIATION_ID_TOO_LONG','RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_CREATED_AT_TOO_LONG']);
});
