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


test('reconciliationStatus reports clear state without exposing mutable mission data',async()=>{
 const r=runtime(valid);
 const result=await r.service.reconciliationStatus('u1','m1');
 assert.deepEqual(result,{missionId:'m1',ownerId:'u1',phase:'clear',recoverable:false,reconciliationId:null,issueCount:0,issueCodes:[],createdAt:null,error:null,storageVersion:1});
});

test('reconciliationStatus reports pending evidence recovery state',async()=>{
 const pending={reconciliationId:'reconcile-1',issues:[{code:'CONTROL_ID_DUPLICATE'}],createdAt:'2026-10-08T00:00:00.000Z'};
 const r=runtime({...valid,controlAuditReconciliationPending:pending,controlAuditReconciliationError:'OBSERVABILITY_DOWN',_storage:{version:7}});
 const result=await r.service.reconciliationStatus('u1','m1');
 assert.equal(result.phase,'pending');
 assert.equal(result.recoverable,true);
 assert.equal(result.reconciliationId,'reconcile-1');
 assert.equal(result.issueCount,1);
 assert.deepEqual(result.issueCodes,['CONTROL_ID_DUPLICATE']);
 assert.equal(result.error,'OBSERVABILITY_DOWN');
 assert.equal(result.storageVersion,7);
 result.issueCodes[0]='MUTATED';
 assert.equal((await r.service.reconciliationStatus('u1','m1')).issueCodes[0],'CONTROL_ID_DUPLICATE');
});

test('reconciliationStatus reports durable error when no pending recovery exists',async()=>{
 const r=runtime({...valid,controlAuditReconciliationError:'OBSERVABILITY_DOWN'});
 const result=await r.service.reconciliationStatus('u1','m1');
 assert.equal(result.phase,'error');
 assert.equal(result.recoverable,false);
 assert.equal(result.error,'OBSERVABILITY_DOWN');
});

test('reconcileAudit is a no-op for a valid durable audit',async()=>{
 const r=runtime(valid);
 const before=r.store.current();
 const result=await r.service.reconcileAudit('u1','m1');
 assert.equal(result.changed,false);
 assert.equal(result.repaired,false);
 assert.equal(result.valid,true);
 assert.equal(r.store.current(),before);
});

test('reconcileAudit persists bounded repair and reports repaired issues',async()=>{
 const broken={...valid,controlHistory:[...valid.controlHistory,{...valid.controlHistory[0]}],controlEvidencePending:{controlId:'missing',action:'pause'},controlEvidenceError:'orphan'};
 const r=runtime(broken);
 const result=await r.service.reconcileAudit('u1','m1');
 assert.equal(result.changed,true);
 assert.equal(result.repaired,true);
 assert.equal(result.valid,true);
 assert.equal(result.remainingIssues.length,0);
 assert.equal(r.store.current().controlHistory.length,1);
 assert.equal(r.store.current().controlEvidencePending,undefined);
});

test('reconcileAudit fails closed when bounded repair cannot clear integrity issues',async()=>{
 const r=runtime({...valid,controlHistory:[]});
 r.service=createMissionControl({
  missionStore:r.store,observability:{async event(){},async snapshot(_o,m){return m;}},
  integrity:{inspect:()=>({valid:false,issues:[{code:'UNREPAIRABLE'}]}),repair:()=>({changed:true,mission:r.store.current(),issues:[{code:'UNREPAIRABLE'}],remainingIssues:[{code:'UNREPAIRABLE'}]})}
 });
 await assert.rejects(()=>r.service.reconcileAudit('u1','m1'),e=>e.code==='MISSION_CONTROL_AUDIT_UNREPAIRABLE');
});

test('reconcileAudit rejects stale writes without mutating current state',async()=>{
 const r=runtime({...valid,controlHistory:[...valid.controlHistory,{...valid.controlHistory[0],controlId:'c1',requestId:'r1'}]});
 const before=r.store.current();
 const originalPut=r.store.putOwned;
 r.store.putOwned=async()=>{const e=new Error('VERSION_CONFLICT');e.code='VERSION_CONFLICT';throw e;};
 await assert.rejects(()=>r.service.reconcileAudit('u1','m1'),e=>e.code==='MISSION_CONTROL_AUDIT_VERSION_CONFLICT');
 assert.deepEqual(r.store.current(),before);
 r.store.putOwned=originalPut;
});


test('reconcileAudit persists before emitting reconciliation evidence',async()=>{
 const broken={...valid,controlHistory:[...valid.controlHistory,{...valid.controlHistory[0]}]};
 const r=runtime(broken);
 const result=await r.service.reconcileAudit('u1','m1');
 assert.equal(result.changed,true);
 assert.equal(result.evidenceRepaired,true);
 assert.equal(r.observability.events.length,1);
 assert.equal(r.observability.events[0].type,'mission_control_audit_reconciled');
 assert.equal(r.store.current().controlAuditReconciliationPending,null);
});

test('reconcileAudit leaves durable pending evidence when observability fails',async()=>{
 const broken={...valid,controlHistory:[...valid.controlHistory,{...valid.controlHistory[0]}]};
 const r=runtime(broken);
 r.observability.event=async()=>{throw new Error('OBSERVABILITY_DOWN')};
 const result=await r.service.reconcileAudit('u1','m1');
 assert.equal(result.changed,true);
 assert.equal(result.evidenceRepaired,false);
 assert.ok(r.store.current().controlAuditReconciliationPending?.reconciliationId);
 assert.equal(r.store.current().controlAuditReconciliationError,'OBSERVABILITY_DOWN');
});

test('reconcileAudit retries pending reconciliation evidence idempotently',async()=>{
 const broken={...valid,controlHistory:[...valid.controlHistory,{...valid.controlHistory[0]}]};
 const r=runtime(broken);
 let fail=true;
 r.observability.event=async(_o,_m,type,payload)=>{if(fail)throw new Error('OBSERVABILITY_DOWN');r.observability.events.push({type,payload});return r.observability.events.at(-1);};
 await r.service.reconcileAudit('u1','m1');
 fail=false;
 const result=await r.service.reconcileAudit('u1','m1');
 assert.equal(result.evidenceRepaired,true);
 assert.equal(r.store.current().controlAuditReconciliationPending,null);
 assert.equal(r.observability.events.length,1);
});

test('reconcileAudit retries a stale repair against a concurrent winner and completes its pending evidence',async()=>{
 const broken={...valid,controlHistory:[...valid.controlHistory,{...valid.controlHistory[0]}]};
 const r=runtime(broken);
 let conflicted=false;
 const originalPut=r.store.putOwned;
 r.store.putOwned=async(scope,owner,id,next,options)=>{
  if(!conflicted && options?.expectedVersion===1){
   conflicted=true;
   await originalPut(scope,owner,id,next,options);
   const winner=r.store.current();
   assert.ok(winner.controlAuditReconciliationPending?.reconciliationId);
   const e=new Error('VERSION_CONFLICT'); e.code='VERSION_CONFLICT'; throw e;
  }
  return originalPut(scope,owner,id,next,options);
 };
 const result=await r.service.reconcileAudit('u1','m1');
 assert.equal(result.reconciledByRetry,true);
 assert.equal(result.evidenceRepaired,true);
 assert.equal(r.store.current().controlAuditReconciliationPending,null);
 assert.equal(r.observability.events.length,1);
});

test('reconcileAudit is idempotent when a concurrent winner already cleared reconciliation evidence',async()=>{
 const broken={...valid,controlHistory:[...valid.controlHistory,{...valid.controlHistory[0]}]};
 const r=runtime(broken);
 let conflicted=false;
 const originalPut=r.store.putOwned;
 r.store.putOwned=async(scope,owner,id,next,options)=>{
  if(!conflicted && options?.expectedVersion===1){
   conflicted=true;
   await originalPut(scope,owner,id,{...valid,_storage:{version:2}}, {overwrite:true,expectedVersion:1});
   const e=new Error('VERSION_CONFLICT'); e.code='VERSION_CONFLICT'; throw e;
  }
  return originalPut(scope,owner,id,next,options);
 };
 const result=await r.service.reconcileAudit('u1','m1');
 assert.equal(result.reconciledByRetry,true);
 assert.equal(result.changed,false);
 assert.equal(result.valid,true);
 assert.equal(r.observability.events.length,0);
});

test('recoverAuditReconciliation recovers pending evidence and reports before/after phases',async()=>{
 const broken={...valid,controlAuditReconciliationPending:{reconciliationId:'reconcile-42',issues:[{code:'CONTROL_ID_DUPLICATE'}],createdAt:'2026-10-08T00:00:00.000Z'},controlAuditReconciliationError:'OBSERVABILITY_DOWN'};
 const r=runtime(broken);
 const result=await r.service.recoverAuditReconciliation('u1','m1');
 assert.equal(result.attempted,true);
 assert.equal(result.recovered,true);
 assert.equal(result.phaseBefore,'pending');
 assert.equal(result.phaseAfter,'clear');
 assert.equal(result.reconciliationId,'reconcile-42');
 assert.equal(result.evidenceRepaired,true);
 assert.equal(r.store.current().controlAuditReconciliationPending,null);
});

test('recoverAuditReconciliation is a read-only no-op when no recovery is pending',async()=>{
 const r=runtime(valid);
 const before=r.store.current();
 const result=await r.service.recoverAuditReconciliation('u1','m1');
 assert.equal(result.attempted,false);
 assert.equal(result.recovered,false);
 assert.equal(result.phase,'clear');
 assert.equal(r.store.current(),before);
});

test('recoverAuditReconciliation preserves durable error state when recovery is not available',async()=>{
 const r=runtime({...valid,controlAuditReconciliationError:'OBSERVABILITY_DOWN'});
 const result=await r.service.recoverAuditReconciliation('u1','m1');
 assert.equal(result.attempted,false);
 assert.equal(result.recovered,false);
 assert.equal(result.phase,'error');
 assert.equal(result.error,'OBSERVABILITY_DOWN');
});
