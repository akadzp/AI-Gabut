import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';
import {createMissionControlIntegrity} from '../../apps/agentic/backend/mission-control-integrity.js';

const pending={reconciliationId:'reconcile-46',phaseBefore:'pending',reconciledByRetry:false,createdAt:'2026-10-08T00:00:00.000Z'};
const base={id:'m1',ownerId:'u1',status:'paused',controlId:'c1',controlHistory:[],_storage:{version:1},controlAuditRecoveryEvidencePending:pending,controlAuditRecoveryEvidenceError:'OBSERVABILITY_DOWN'};
function runtime(initial,behavior){
 let current={...initial}; let puts=0;
 const store={
  async getOwned(_s,_o,id){return id===current.id?current:null;},
  async putOwned(_s,_o,_id,next){puts++; return behavior(next,puts,()=>current,v=>{current=v;});},
  current:()=>current
 };
 const observability={async event(){},async snapshot(_o,m){return m;}};
 const service=createMissionControl({missionStore:store,observability,integrity:createMissionControlIntegrity(),clock:()=> '2026-10-08T00:00:00.000Z'});
 return {store,service};
}

test('version conflict retries against a fresh winner and becomes a no-op',async()=>{
 const r=runtime(base,(next,puts,getCurrent,setCurrent)=>{
  if(puts===1){setCurrent({...getCurrent(),controlAuditRecoveryEvidenceError:null,_storage:{version:2}});const e=new Error('VERSION_CONFLICT');e.code='VERSION_CONFLICT';throw e;}
  setCurrent({...next,_storage:{version:3}});return getCurrent();
 });
 const result=await r.service.repairAuditRecoveryEvidence('u1','m1');
 assert.equal(result.changed,false);assert.equal(result.repaired,false);assert.equal(result.repairedByRetry,true);assert.equal(r.store.current().controlAuditRecoveryEvidenceError,null);
});

test('version conflict retries when winner preserves error and repair remains necessary',async()=>{
 const r=runtime(base,(next,puts,getCurrent,setCurrent)=>{
  if(puts===1){setCurrent({...getCurrent(),_storage:{version:2}});const e=new Error('VERSION_CONFLICT');e.code='VERSION_CONFLICT';throw e;}
  setCurrent({...next,_storage:{version:3}});return getCurrent();
 });
 const result=await r.service.repairAuditRecoveryEvidence('u1','m1');
 assert.equal(result.changed,true);assert.equal(result.repaired,true);assert.equal(result.repairedByRetry,true);assert.equal(r.store.current().controlAuditRecoveryEvidenceError,null);
});

test('repeated version conflicts fail closed without mutation',async()=>{
 const r=runtime(base,(_next,_puts,_getCurrent)=>{const e=new Error('VERSION_CONFLICT');e.code='VERSION_CONFLICT';throw e;});
 await assert.rejects(()=>r.service.repairAuditRecoveryEvidence('u1','m1'),e=>e.code==='MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_VERSION_CONFLICT');
 assert.equal(r.store.current().controlAuditRecoveryEvidenceError,'OBSERVABILITY_DOWN');
});
