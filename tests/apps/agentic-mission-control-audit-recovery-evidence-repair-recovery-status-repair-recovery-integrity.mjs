import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';

function runtime(initial){
 let current={...initial};
 const store={
  async getOwned(_scope,_owner,id){if(id!==current.id||_owner!==current.ownerId)return null;return current;},
  async putOwned(){throw new Error('MUTATION_NOT_EXPECTED');},
  current:()=>current
 };
 const observability={async event(){throw new Error('EVENT_NOT_EXPECTED');},async snapshot(_o,m){return m;}};
 return {store,service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-09T00:00:00.000Z'})};
}
const base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:12}};
const pending={reconciliationId:'reconcile-56',recoveredByRetry:true,createdAt:'2026-10-09T00:00:00.000Z'};

test('batch 57 verifies pending recovery-status-repair recovery observability without mutation',async()=>{
 const r=runtime({...base,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending:pending,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError:'OBSERVABILITY_DOWN'});
 const before=r.store.current();
 const out=await r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.valid,true); assert.equal(out.pending,true); assert.equal(out.reconciliationId,'reconcile-56');
 assert.equal(out.dedupeKey,'control-audit-recovery-repair-recovery-status-recovered:m1'); assert.deepEqual(out.issues,[]); assert.strictEqual(r.store.current(),before);
});

test('batch 57 detects malformed recovery-status-repair recovery intent',async()=>{
 const r=runtime({...base,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending:{reconciliationId:'',recoveredByRetry:'yes',createdAt:''}});
 const out=await r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.valid,false);
 assert.deepEqual(out.issues.map(x=>x.code),['RECOVERY_STATUS_REPAIR_RECOVERY_RECONCILIATION_ID_MISSING','RECOVERY_STATUS_REPAIR_RECOVERY_RETRY_FLAG_INVALID','RECOVERY_STATUS_REPAIR_RECOVERY_CREATED_AT_MISSING']);
});

test('batch 57 fails closed for orphaned recovery-status-repair recovery error and remains owner scoped',async()=>{
 const r=runtime({...base,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError:'EVENT_DOWN'});
 const out=await r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.valid,false); assert.equal(out.pending,false); assert.equal(out.issues[0].code,'RECOVERY_STATUS_REPAIR_RECOVERY_ERROR_WITHOUT_PENDING');
 await assert.rejects(()=>r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatus('u2','m1'),e=>e.code==='MISSION_NOT_FOUND');
});
