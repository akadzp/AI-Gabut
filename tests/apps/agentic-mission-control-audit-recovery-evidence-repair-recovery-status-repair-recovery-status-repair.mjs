import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';

function runtime(initial){
 let current={...initial};
 const store={
  async getOwned(_scope,_owner,id){if(id!==current.id||_owner!==current.ownerId)return null;return current;},
  async putOwned(_scope,_owner,id,next){assert.equal(id,current.id);current={...next,_storage:{...next._storage,version:(current._storage?.version||0)+1}};return current;},
  current:()=>current
 };
 const observability={async event(){return null;},async snapshot(_o,m){return m;}};
 return {store,service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-09T00:00:00.000Z'})};
}
const base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:14}};
const pending={reconciliationId:'reconcile-57',recoveredByRetry:true,createdAt:'2026-10-09T00:00:00.000Z'};

test('batch 58 repairs orphaned recovery-status-repair recovery observability error',async()=>{
 const r=runtime({...base,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError:'EVENT_DOWN'});
 const out=await r.service.repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.changed,true); assert.equal(out.repaired,true); assert.equal(out.pending,false); assert.equal(out.error,null);
 assert.equal(r.store.current().controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError,null);
});

test('batch 58 does not mutate pending recovery-status-repair recovery observability intent',async()=>{
 const r=runtime({...base,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairPending:pending,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairError:'EVENT_DOWN'});
 const before=r.store.current();
 const out=await r.service.repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.changed,false); assert.equal(out.repaired,false); assert.equal(out.pending,true); assert.equal(out.error,'EVENT_DOWN');
 assert.strictEqual(r.store.current(),before);
});

test('batch 58 is a no-op when recovery-status-repair recovery observability state is clear',async()=>{
 const r=runtime(base); const before=r.store.current();
 const out=await r.service.repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatus('u1','m1');
 assert.equal(out.changed,false); assert.equal(out.repaired,false); assert.equal(out.pending,false); assert.equal(out.error,null); assert.strictEqual(r.store.current(),before);
});
