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

test('clear recovery evidence is valid and read-only',async()=>{
 const r=runtime(valid);
 const result=await r.service.verifyAuditRecoveryEvidence('u1','m1');
 assert.deepEqual(result,{missionId:'m1',ownerId:'u1',valid:true,pending:false,reconciliationId:null,issues:[]});
 assert.equal(r.store.current().controlAuditRecoveryEvidencePending,undefined);
});

test('valid pending recovery evidence exposes deterministic dedupe key',async()=>{
 const r=runtime({...valid,controlAuditRecoveryEvidencePending:{reconciliationId:'reconcile-44',phaseBefore:'pending',reconciledByRetry:false,createdAt:'2026-10-08T00:00:00.000Z'}});
 const result=await r.service.verifyAuditRecoveryEvidence('u1','m1');
 assert.equal(result.valid,true);
 assert.equal(result.dedupeKey,'control-audit-recovery:reconcile-44');
});

test('malformed pending recovery evidence is detected without mutation',async()=>{
 const pending={reconciliationId:'',phaseBefore:'unknown',reconciledByRetry:'no',createdAt:''};
 const r=runtime({...valid,controlAuditRecoveryEvidencePending:pending});
 const result=await r.service.verifyAuditRecoveryEvidence('u1','m1');
 assert.equal(result.valid,false);
 assert.deepEqual(result.issues.map(x=>x.code),['RECOVERY_EVIDENCE_RECONCILIATION_ID_MISSING','RECOVERY_EVIDENCE_PHASE_INVALID','RECOVERY_EVIDENCE_RETRY_FLAG_INVALID','RECOVERY_EVIDENCE_CREATED_AT_MISSING']);
 assert.deepEqual(r.store.current().controlAuditRecoveryEvidencePending,pending);
});
