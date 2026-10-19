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

const base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:13}};
const pending={reconciliationId:'recon-60',createdAt:'2026-10-09T00:00:00.000Z',repairedByRetry:true};
const pendingKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending';
const errorKey='controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError';

test('batch 61 reports clear recovery status without mutation or emission',async()=>{
 const r=runtime(base);const before=r.store.current();
 const out=await r.service.auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.deepEqual(out,{missionId:'m1',ownerId:'u1',phase:'clear',recoverable:false,reconciliationId:null,repairedByRetry:false,createdAt:null,error:null,storageVersion:13});
 assert.strictEqual(r.store.current(),before);
});

test('batch 61 reports pending Batch 60 recovery intent with bounded metadata',async()=>{
 const r=runtime({...base,[pendingKey]:pending,[errorKey]:'EVENT_DOWN'});const before=r.store.current();
 const out=await r.service.auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.phase,'pending');assert.equal(out.recoverable,true);assert.equal(out.reconciliationId,'recon-60');
 assert.equal(out.repairedByRetry,true);assert.equal(out.createdAt,pending.createdAt);assert.equal(out.error,'EVENT_DOWN');
 assert.equal(out.storageVersion,13);assert.strictEqual(r.store.current(),before);
});

test('batch 61 reports orphaned durable error when no recovery intent exists',async()=>{
 const r=runtime({...base,[errorKey]:'EVENT_DOWN'});const before=r.store.current();
 const out=await r.service.auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.phase,'error');assert.equal(out.recoverable,false);assert.equal(out.error,'EVENT_DOWN');
 assert.equal(out.reconciliationId,null);assert.strictEqual(r.store.current(),before);
});

test('batch 61 status view remains owner-scoped',async()=>{
 const r=runtime(base);
 await assert.rejects(()=>r.service.auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus('u2','m1'),e=>e.code==='MISSION_NOT_FOUND');
});

test('batch 61 bounds metadata returned from malformed oversized fields',async()=>{
 const r=runtime({...base,[pendingKey]:{reconciliationId:'r'.repeat(250),createdAt:'t'.repeat(130),repairedByRetry:false},[errorKey]:'e'.repeat(1100)});
 const out=await r.service.auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.reconciliationId.length,200);assert.equal(out.createdAt.length,100);assert.equal(out.error.length,1000);
 assert.equal(out.phase,'pending');assert.equal(out.recoverable,true);
});
