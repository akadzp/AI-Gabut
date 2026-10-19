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
 const observability={events:[],async event(_o,_m,type,payload){this.events.push({type,payload});return this.events.at(-1);},async snapshot(_o,m){return m;}};
 return {store,observability,service:createMissionControl({missionStore:store,observability,integrity:createMissionControlIntegrity(),clock:()=> '2026-10-08T00:00:00.000Z'})};
}

const valid={id:'m1',ownerId:'u1',status:'paused',controlId:'c1',controlReason:'hold',controlRequestId:'r1',controlHistory:[{controlId:'c1',action:'pause',reason:'hold',requestId:'r1',createdAt:'2026-10-08T00:00:00.000Z'}],_storage:{version:1}};

test('recovery emits owner-scoped completion evidence with deterministic dedupe',async()=>{
 const broken={...valid,controlHistory:[...valid.controlHistory,{...valid.controlHistory[0]}],controlAuditReconciliationPending:{reconciliationId:'reconcile-43',issues:[{code:'CONTROL_ID_DUPLICATE'}],createdAt:'2026-10-08T00:00:00.000Z'},controlAuditReconciliationError:'OBSERVABILITY_DOWN'};
 const r=runtime(broken);
 const result=await r.service.recoverAuditReconciliation('u1','m1');
 assert.equal(result.recovered,true);
 assert.equal(result.recoveryEvidenceRepaired,true);
 assert.equal(r.observability.events.length,2);
 const event=r.observability.events[1];
 assert.equal(event.type,'mission_control_audit_recovery_completed');
 assert.equal(event.payload.reconciliationId,'reconcile-43');
 assert.equal(event.payload.dedupeKey,'control-audit-recovery:reconcile-43');
 assert.equal(r.store.current().controlAuditRecoveryEvidencePending,null);
});

test('recovery evidence failure leaves durable pending evidence without undoing reconciliation',async()=>{
 const broken={...valid,controlHistory:[...valid.controlHistory,{...valid.controlHistory[0]}],controlAuditReconciliationPending:{reconciliationId:'reconcile-fail',issues:[{code:'CONTROL_ID_DUPLICATE'}],createdAt:'2026-10-08T00:00:00.000Z'},controlAuditReconciliationError:'OBSERVABILITY_DOWN'};
 const r=runtime(broken);
 r.observability.event=async(_o,_m,type,payload)=>{if(type==='mission_control_audit_recovery_completed') throw new Error('OBSERVABILITY_DOWN');r.observability.events.push({type,payload});return r.observability.events.at(-1);};
 const result=await r.service.recoverAuditReconciliation('u1','m1');
 assert.equal(result.recovered,true);
 assert.equal(result.recoveryEvidenceRepaired,false);
 assert.equal(r.store.current().controlAuditReconciliationPending,null);
 assert.equal(r.store.current().controlAuditRecoveryEvidencePending.reconciliationId,'reconcile-fail');
 assert.equal(r.store.current().controlAuditRecoveryEvidenceError,'OBSERVABILITY_DOWN');
});

test('recovery retries pending recovery evidence without rerunning reconciliation',async()=>{
 const broken={...valid,controlAuditRecoveryEvidencePending:{reconciliationId:'reconcile-retry',phaseBefore:'pending',reconciledByRetry:false,createdAt:'2026-10-08T00:00:00.000Z'},controlAuditRecoveryEvidenceError:'OBSERVABILITY_DOWN'};
 const r=runtime(broken);
 const result=await r.service.recoverAuditReconciliation('u1','m1');
 assert.equal(result.attempted,false);
 assert.equal(result.recoveryEvidenceRepaired,true);
 assert.equal(result.recoveryEvidenceReconciledByRetry,false);
 assert.equal(r.observability.events.length,1);
 assert.equal(r.observability.events[0].payload.dedupeKey,'control-audit-recovery:reconcile-retry');
 assert.equal(r.store.current().controlAuditRecoveryEvidencePending,null);
});
