import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';
import {createMissionControlIntegrity} from '../../apps/agentic/backend/mission-control-integrity.js';

function runtime(initial,{failEvent=false}={}){
 let current={...initial}; const events=[];
 const store={
  async getOwned(_scope,_owner,id){return id===current.id?current:null;},
  async putOwned(_scope,_owner,id,next){current={...next,_storage:{version:(current._storage?.version||0)+1}};return current;},
  current:()=>current
 };
 const observability={async event(_o,_id,type,payload){if(failEvent) throw new Error('OBSERVABILITY_DOWN');events.push({type,payload});},async snapshot(_o,m){return m;}};
 return {store,events,service:createMissionControl({missionStore:store,observability,integrity:createMissionControlIntegrity(),clock:()=> '2026-10-08T00:00:00.000Z'})};
}
const valid={id:'m1',ownerId:'u1',status:'paused',controlId:'c1',controlHistory:[],_storage:{version:1}};
const pending={reconciliationId:'reconcile-47',phaseBefore:'pending',reconciledByRetry:false,createdAt:'2026-10-08T00:00:00.000Z'};

test('repair emits deterministic owner-scoped evidence and clears repair intent',async()=>{
 const r=runtime({...valid,controlAuditRecoveryEvidencePending:pending,controlAuditRecoveryEvidenceError:'OBSERVABILITY_DOWN'});
 const result=await r.service.repairAuditRecoveryEvidence('u1','m1');
 assert.equal(result.repaired,true); assert.equal(r.events.length,1);
 assert.equal(r.events[0].type,'mission_control_audit_recovery_evidence_repaired');
 assert.equal(r.events[0].payload.dedupeKey,'control-audit-recovery-repair:reconcile-47');
 assert.equal(r.store.current().controlAuditRecoveryEvidenceRepairPending,null);
 assert.equal(r.store.current().controlAuditRecoveryEvidenceError,null);
});

test('successful repair remains durable when observability fails and leaves retryable repair intent',async()=>{
 const r=runtime({...valid,controlAuditRecoveryEvidencePending:pending,controlAuditRecoveryEvidenceError:'OBSERVABILITY_DOWN'},{failEvent:true});
 const result=await r.service.repairAuditRecoveryEvidence('u1','m1');
 assert.equal(result.repaired,true);
 assert.equal(r.store.current().controlAuditRecoveryEvidenceError,null);
 assert.deepEqual(r.store.current().controlAuditRecoveryEvidencePending,pending);
 assert.equal(r.store.current().controlAuditRecoveryEvidenceRepairPending.reconciliationId,'reconcile-47');
 assert.equal(r.store.current().controlAuditRecoveryEvidenceRepairError,'OBSERVABILITY_DOWN');
});

test('retry of pending repair evidence does not rerun repair and is idempotent',async()=>{
 const r=runtime({...valid,controlAuditRecoveryEvidencePending:pending,controlAuditRecoveryEvidenceError:null,controlAuditRecoveryEvidenceRepairPending:{...pending,repairedByRetry:false},controlAuditRecoveryEvidenceRepairError:'OBSERVABILITY_DOWN'});
 const result=await r.service.repairAuditRecoveryEvidence('u1','m1');
 assert.equal(result.changed,false); assert.equal(result.repaired,false);
 assert.equal(r.events.length,1);
 assert.equal(r.events[0].type,'mission_control_audit_recovery_evidence_repaired');
 assert.equal(r.store.current().controlAuditRecoveryEvidenceRepairPending,null);
});
