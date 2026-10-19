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
const base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:9}};
const pending={reconciliationId:'reconcile-51',recoveredByRetry:true,createdAt:'2026-10-08T00:00:00.000Z'};

test('repair recovery observability status reports clear state without mutation',async()=>{
 const r=runtime(base); const before=r.store.current();
 const out=await r.service.auditRecoveryEvidenceRepairRecoveryStatus('u1','m1');
 assert.deepEqual(out,{missionId:'m1',ownerId:'u1',phase:'clear',recoverable:false,reconciliationId:null,recoveredByRetry:false,createdAt:null,error:null,storageVersion:9});
 assert.strictEqual(r.store.current(),before);
});

test('repair recovery observability status reports pending intent',async()=>{
 const r=runtime({...base,controlAuditRecoveryEvidenceRepairRecoveryPending:pending,controlAuditRecoveryEvidenceRepairRecoveryError:'OBSERVABILITY_DOWN'});
 const out=await r.service.auditRecoveryEvidenceRepairRecoveryStatus('u1','m1');
 assert.equal(out.phase,'pending'); assert.equal(out.recoverable,true); assert.equal(out.reconciliationId,'reconcile-51');
 assert.equal(out.recoveredByRetry,true); assert.equal(out.error,'OBSERVABILITY_DOWN');
});

test('repair recovery observability status is owner scoped and reports error state',async()=>{
 const r=runtime({...base,controlAuditRecoveryEvidenceRepairRecoveryError:'OBSERVABILITY_DOWN'});
 const out=await r.service.auditRecoveryEvidenceRepairRecoveryStatus('u1','m1');
 assert.equal(out.phase,'error'); assert.equal(out.recoverable,false); assert.equal(out.error,'OBSERVABILITY_DOWN');
 await assert.rejects(()=>r.service.auditRecoveryEvidenceRepairRecoveryStatus('u2','m1'),e=>e.code==='FORBIDDEN');
});
