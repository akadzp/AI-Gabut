import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';
import {createMissionControlIntegrity} from '../../apps/agentic/backend/mission-control-integrity.js';

function runtime(initial){
 let current={...initial};
 const store={
  async getOwned(_scope,_owner,id){return id===current.id?current:null;},
  async putOwned(_scope,_owner,id,next){current={...next,_storage:{version:(current._storage?.version||0)+1}};return current;},
  current:()=>current
 };
 const observability={async event(){},async snapshot(_o,m){return m;}};
 return {store,service:createMissionControl({missionStore:store,observability,integrity:createMissionControlIntegrity(),clock:()=> '2026-10-08T00:00:00.000Z'})};
}

const valid={id:'m1',ownerId:'u1',status:'paused',controlId:'c1',controlHistory:[],_storage:{version:1}};
const pending={reconciliationId:'reconcile-45',phaseBefore:'pending',reconciledByRetry:false,createdAt:'2026-10-08T00:00:00.000Z'};

test('valid recovery evidence with stale error marker is repaired without touching pending evidence',async()=>{
 const r=runtime({...valid,controlAuditRecoveryEvidencePending:pending,controlAuditRecoveryEvidenceError:'OBSERVABILITY_DOWN'});
 const result=await r.service.repairAuditRecoveryEvidence('u1','m1');
 assert.equal(result.changed,true);
 assert.equal(result.repaired,true);
 assert.equal(r.store.current().controlAuditRecoveryEvidenceError,null);
 assert.deepEqual(r.store.current().controlAuditRecoveryEvidencePending,pending);
});

test('valid recovery evidence without an error marker is a no-op',async()=>{
 const r=runtime({...valid,controlAuditRecoveryEvidencePending:pending});
 const result=await r.service.repairAuditRecoveryEvidence('u1','m1');
 assert.equal(result.changed,false);
 assert.equal(result.repaired,false);
 assert.deepEqual(r.store.current().controlAuditRecoveryEvidencePending,pending);
});

test('malformed recovery evidence fails closed without mutation',async()=>{
 const malformed={reconciliationId:'',phaseBefore:'broken',reconciledByRetry:'no',createdAt:''};
 const r=runtime({...valid,controlAuditRecoveryEvidencePending:malformed,controlAuditRecoveryEvidenceError:'BAD'});
 await assert.rejects(()=>r.service.repairAuditRecoveryEvidence('u1','m1'),error=>error.code==='MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_UNREPAIRABLE');
 assert.deepEqual(r.store.current().controlAuditRecoveryEvidencePending,malformed);
 assert.equal(r.store.current().controlAuditRecoveryEvidenceError,'BAD');
});
