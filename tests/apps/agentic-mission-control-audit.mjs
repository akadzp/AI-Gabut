import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';

function runtime(initial={id:'m1',ownerId:'u1',status:'running',controlHistory:[]}){
 const records=new Map([['missions:u1:m1',initial]]);
 const store={
  async getOwned(scope,owner,id){return records.get(`${scope}:${owner}:${id}`)||null;},
  async putOwned(scope,owner,id,value){records.set(`${scope}:${owner}:${id}`,value);return value;}
 };
 const observability={async event(){},async snapshot(_o,m){return m;}};
 return {service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-08T00:00:00.000Z'}),store};
}

test('audit returns immutable copies of mission control history with summary metadata',async()=>{
 const r=runtime();
 await r.service.control('u1','m1','pause',{requestId:'r1',reason:'hold'});
 await r.service.control('u1','m1','resume',{requestId:'r2',reason:'continue'});
 const audit=await r.service.audit('u1','m1');
 assert.equal(audit.missionId,'m1');
 assert.equal(audit.ownerId,'u1');
 assert.equal(audit.missionStatus,'running');
 assert.equal(audit.entries.length,2);
 assert.equal(audit.total,2);
 assert.equal(audit.currentControlId,audit.entries.at(-1).controlId);
 audit.entries[0].action='cancel';
 const again=await r.service.audit('u1','m1');
 assert.equal(again.entries[0].action,'pause');
});

test('audit supports bounded action filtering and limit without mutating mission state',async()=>{
 const r=runtime();
 await r.service.control('u1','m1','pause','hold');
 await r.service.control('u1','m1','resume','continue');
 await r.service.control('u1','m1','pause','hold again');
 const before=await r.store.getOwned('missions','u1','m1');
 const audit=await r.service.audit('u1','m1',{action:'pause',limit:1});
 assert.equal(audit.total,2);
 assert.equal(audit.entries.length,1);
 assert.equal(audit.entries[0].reason,'hold again');
 const after=await r.store.getOwned('missions','u1','m1');
 assert.deepEqual(after,before);
});

test('audit remains owner-scoped and unknown action does not broaden privileged access',async()=>{
 const r=runtime();
 await assert.rejects(()=>r.service.audit('u2','m1'),e=>e.code==='MISSION_NOT_FOUND');
 await r.service.control('u1','m1','pause','hold');
 const audit=await r.service.audit('u1','m1',{action:'unknown'});
 assert.equal(audit.entries.length,1);
});


test('verifyAudit validates the durable control audit without mutating mission state',async()=>{
 const r=runtime();
 await r.service.control('u1','m1','pause',{requestId:'r1',reason:'hold'});
 const mission=await r.store.getOwned('missions','u1','m1');
 const integrity={inspect(_owner,m){
   return {valid:Array.isArray(m.controlHistory)&&m.controlHistory.length===1,issues:Array.isArray(m.controlHistory)?[]:[{code:'CONTROL_HISTORY_INVALID'}]};
 }};
 const service=createMissionControl({missionStore:r.store,observability:{async event(){},async snapshot(_o,m){return m;}},integrity});
 const before=await r.store.getOwned('missions','u1','m1');
 const audit=await service.verifyAudit('u1','m1');
 assert.equal(audit.valid,true);
 assert.equal(audit.checkedEntries,1);
 assert.deepEqual(await r.store.getOwned('missions','u1','m1'),before);
});

test('verifyAudit reports integrity issues without repairing them',async()=>{
 const records=new Map([['missions:u1:m1',{id:'m1',ownerId:'u1',status:'paused',controlId:'c1',controlReason:'hold',controlHistory:[{controlId:'c1',action:'pause',reason:'hold',createdAt:'bad'}]}]]);
 const store={async getOwned(scope,owner,id){return records.get(`${scope}:${owner}:${id}`)||null;},async putOwned(){throw new Error('must not write');}};
 const integrity={inspect(){return {valid:false,issues:[{code:'CONTROL_CREATED_AT_INVALID',path:'controlHistory[0].createdAt'}]};}};
 const service=createMissionControl({missionStore:store,observability:{async event(){}},integrity});
 const audit=await service.verifyAudit('u1','m1');
 assert.equal(audit.valid,false);
 assert.equal(audit.checkedEntries,1);
 assert.equal(audit.issues[0].code,'CONTROL_CREATED_AT_INVALID');
});
