import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';

function runtime(initial){
 let current={...initial};
 const store={
  async getOwned(_scope,_owner,id){if(id!==current.id)return null;if(_owner!==current.ownerId)return null;return current;},
  async putOwned(){throw new Error('MUTATION_NOT_EXPECTED');},
  current:()=>current
 };
 const observability={async event(){throw new Error('EVENT_NOT_EXPECTED');},async snapshot(_o,m){return m;}};
 return {store,service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-08T00:00:00.000Z'})};
}
const base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:9}};
const pending={reconciliationId:'reconcile-52',recoveredByRetry:true,createdAt:'2026-10-08T00:00:00.000Z'};

test('repair recovery status integrity validates a pending intent without mutation',async()=>{
 const r=runtime({...base,controlAuditRecoveryEvidenceRepairRecoveryPending:pending,controlAuditRecoveryEvidenceRepairRecoveryError:'OBSERVABILITY_DOWN'});
 const before=r.store.current();
 const out=await r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatus('u1','m1');
 assert.equal(out.valid,true); assert.equal(out.pending,true); assert.equal(out.reconciliationId,'reconcile-52');
 assert.equal(out.dedupeKey,'control-audit-recovery-repair-recovery:reconcile-52'); assert.deepEqual(out.issues,[]); assert.strictEqual(r.store.current(),before);
});

test('repair recovery status integrity detects malformed pending intent',async()=>{
 const r=runtime({...base,controlAuditRecoveryEvidenceRepairRecoveryPending:{reconciliationId:'',recoveredByRetry:'yes',createdAt:''}});
 const out=await r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatus('u1','m1');
 assert.equal(out.valid,false); assert.deepEqual(out.issues.map(x=>x.code),['RECOVERY_REPAIR_RECOVERY_RECONCILIATION_ID_MISSING','RECOVERY_REPAIR_RECOVERY_RETRY_FLAG_INVALID','RECOVERY_REPAIR_RECOVERY_CREATED_AT_MISSING']);
});

test('repair recovery status integrity fails closed for orphaned error and remains owner scoped',async()=>{
 const r=runtime({...base,controlAuditRecoveryEvidenceRepairRecoveryError:'OBSERVABILITY_DOWN'});
 const out=await r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatus('u1','m1');
 assert.equal(out.valid,false); assert.equal(out.pending,false); assert.equal(out.issues[0].code,'RECOVERY_REPAIR_RECOVERY_ERROR_WITHOUT_PENDING');
 await assert.rejects(()=>r.service.verifyAuditRecoveryEvidenceRepairRecoveryStatus('u2','m1'),e=>e.code==='MISSION_NOT_FOUND');
});
