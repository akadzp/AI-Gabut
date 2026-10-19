import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';

function runtime(initial){
 let current={...initial};
 const store={
  async getOwned(_scope,_owner,id){return id===current.id?current:null;},
  async putOwned(_scope,_owner,id,next){current={...next,_storage:{version:(current._storage?.version||0)+1}};return current;},
  current:()=>current
 };
 const observability={async event(){},async snapshot(_o,m){return m;}};
 return {store,service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-08T00:00:00.000Z'})};
}
const base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:7}};
const pending={reconciliationId:'reconcile-48',phaseBefore:'pending',reconciledByRetry:false,repairedByRetry:false,createdAt:'2026-10-08T00:00:00.000Z'};

test('repair evidence status reports clear state without mutation',async()=>{
 const r=runtime(base); const before=r.store.current();
 const out=await r.service.auditRecoveryEvidenceRepairStatus('u1','m1');
 assert.deepEqual(out,{missionId:'m1',ownerId:'u1',phase:'clear',recoverable:false,reconciliationId:null,phaseBefore:null,reconciledByRetry:false,repairedByRetry:false,createdAt:null,error:null,storageVersion:7});
 assert.strictEqual(r.store.current(),before);
});

test('repair evidence status reports pending recovery intent',async()=>{
 const r=runtime({...base,controlAuditRecoveryEvidenceRepairPending:pending,controlAuditRecoveryEvidenceRepairError:'OBSERVABILITY_DOWN'});
 const out=await r.service.auditRecoveryEvidenceRepairStatus('u1','m1');
 assert.equal(out.phase,'pending'); assert.equal(out.recoverable,true); assert.equal(out.reconciliationId,'reconcile-48');
 assert.equal(out.error,'OBSERVABILITY_DOWN'); assert.equal(out.phaseBefore,'pending');
});

test('repair evidence status is owner scoped and exposes retry metadata',async()=>{
 const r=runtime({...base,controlAuditRecoveryEvidenceRepairPending:{...pending,reconciledByRetry:true,repairedByRetry:true}});
 const out=await r.service.auditRecoveryEvidenceRepairStatus('u1','m1');
 assert.equal(out.reconciledByRetry,true); assert.equal(out.repairedByRetry,true); assert.equal(out.storageVersion,7);
 await assert.rejects(()=>r.service.auditRecoveryEvidenceRepairStatus('u2','m1'),e=>e.code==='FORBIDDEN');
});
