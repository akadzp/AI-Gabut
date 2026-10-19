import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';

function runtime(initial,emit){
 let current={...initial};
 const events=[];
 const store={
  async getOwned(_s,_o,id){if(id!==current.id||_o!==current.ownerId)return null;return current;},
  async putOwned(_s,_o,_id,next,options={}){
   if(options.expectedVersion!==undefined&&options.expectedVersion!==current._storage?.version){const error=new Error('VERSION_CONFLICT');error.code='VERSION_CONFLICT';throw error;}
   current={...next,_storage:{...(next._storage||{}),version:(current._storage?.version||0)+1}};
   return current;
  },
  current:()=>current
 };
 const observability={event:async(...args)=>{events.push(args);return emit?emit(...args):{ok:true};},snapshot:async(_o,m)=>m};
 return {store,service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-09T00:00:00.000Z'}),events};
}

const base={id:'m1',ownerId:'u1',status:'paused',controlHistory:[],_storage:{version:11}};
const pending={reconciliationId:'recon-59',createdAt:'2026-10-09T00:00:00.000Z',repairedByRetry:true};
const pendingState={controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending:pending,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError:'EVENT_DOWN'};

test('batch 60 recovers pending Batch 59 observability intent with the same deterministic event key',async()=>{
 const r=runtime({...base,...pendingState});
 const out=await r.service.recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepair('u1','m1');
 assert.equal(out.attempted,true);assert.equal(out.recovered,true);assert.equal(out.phase,'clear');assert.equal(out.observabilityEmitted,true);
 assert.equal(r.events.length,1);assert.equal(r.events[0][2],'mission_control_audit_recovery_evidence_repair_recovery_status_repair_repaired');
 assert.equal(r.events[0][3].dedupeKey,'control-audit-recovery-repair-recovery-status-repair:m1');assert.equal(r.events[0][3].reconciliationId,'recon-59');
 assert.equal(r.store.current().controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending,null);
 assert.equal(r.store.current().controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError,null);
});

test('batch 60 retains durable intent and error when recovery emission fails',async()=>{
 const r=runtime({...base,...pendingState},async()=>{throw new Error('EVENT_STILL_DOWN');});
 const out=await r.service.recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepair('u1','m1');
 assert.equal(out.attempted,true);assert.equal(out.recovered,false);assert.equal(out.phase,'pending');assert.equal(out.observabilityEmitted,false);
 assert.deepEqual(r.store.current().controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending,pending);
 assert.equal(r.store.current().controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError,'EVENT_STILL_DOWN');
});

test('batch 60 is a read-only no-op without a pending recovery intent',async()=>{
 const r=runtime({...base,controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError:'ORPHANED_ERROR'});
 const before=r.store.current();
 const out=await r.service.recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepair('u1','m1');
 assert.equal(out.attempted,false);assert.equal(out.recovered,false);assert.equal(out.phase,'error');assert.equal(r.events.length,0);assert.strictEqual(r.store.current(),before);
});

test('batch 60 fails closed on malformed pending intent without mutation or emission',async()=>{
 const malformed={controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairPending:{reconciliationId:'r1'},controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairError:'EVENT_DOWN'};
 const r=runtime({...base,...malformed});
 const before=r.store.current();
 await assert.rejects(()=>r.service.recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepair('u1','m1'),{code:'MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_UNREPAIRABLE'});
 assert.equal(r.events.length,0);assert.strictEqual(r.store.current(),before);
});
