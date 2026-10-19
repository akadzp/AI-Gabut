import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionScheduler} from '../../apps/agentic/backend/mission-scheduler.js';
import {createMissionApprovalService} from '../../apps/agentic/backend/mission-approval.js';
import {createMissionApprovalExpiryService} from '../../apps/agentic/backend/mission-approval-expiry.js';
import {createMissionObservability} from '../../apps/agentic/backend/mission-observability.js';

function runtime(){
  let now=Date.parse('2026-10-07T01:00:00.000Z');
  let mission={id:'m1',ownerId:'u1',status:'scheduled',currentStageIndex:0,nextRunAt:new Date(now).toISOString(),cadenceMs:3600000,stages:[{id:'s1',state:'pending',workId:'w1'}],history:[],approval:null,updatedAt:new Date(now).toISOString(),_storage:{version:1}};
  const approvals=new Map(); const events=new Map();
  const store={
    async getMission(o,id){return o==='u1'&&id==='m1'?mission:null},
    async putMission(_o,m){mission={...m,_storage:{version:(mission._storage?.version||0)+1}};return mission},
    async listMissions(o){return o==='u1'?[mission]:[]},
    async putMissionApproval(_o,a){approvals.set(a.id,a);return a},
    async getMissionApproval(_o,id){return approvals.get(id)||null},
    async listMissionApprovals(){return [...approvals.values()]},
    async putOwned(scope,_o,id,v){events.set(id,v);return v},
    async listOwned(scope){return [...events.values()]}
  };
  const observability=createMissionObservability({store,realtime:null,clock:()=>new Date(now).toISOString()});
  const journal={async begin(){return{state:'running'}},async finalize(){},async reopen(){}};
  const scheduler=createMissionScheduler({store,observability,journalService:journal,clock:()=>now,runWork:async()=>({status:'waiting_approval',approval:{required:true,expiresAt:new Date(now+1000).toISOString()}})});
  const approval=createMissionApprovalService({store,journalService:journal,observability,clock:()=>now});
  const expiry=createMissionApprovalExpiryService({store,observability,clock:()=>now+2000});
  return {store,observability,scheduler,approval,expiry,advance(ms){now+=ms},mission:()=>mission};
}

test('approval request and decision are durable observability events',async()=>{
  const r=runtime();
  await r.scheduler.tick('u1','m1');
  let events=await r.observability.timeline('u1','m1');
  assert.equal(events.at(-1).type,'approval_requested');
  await r.approval.approve('u1','m1','operator approved');
  events=await r.observability.timeline('u1','m1');
  assert.equal(events.at(-1).type,'approval_resolved');
  assert.equal(events.at(-1).payload.status,'approved');
});

test('approval expiry records a resolved observability event',async()=>{
  const r=runtime();
  await r.scheduler.tick('u1','m1');
  await r.expiry.expireDue('u1');
  const events=await r.observability.timeline('u1','m1');
  assert.equal(events.at(-1).type,'approval_resolved');
  assert.equal(events.at(-1).payload.status,'expired');
});

test('snapshot exposes approval requirement from mission state',async()=>{
  const r=runtime();
  await r.scheduler.tick('u1','m1');
  const snapshot=await r.observability.snapshot('u1',r.mission());
  assert.equal(snapshot.status,'waiting_approval');
  assert.equal(snapshot.approvalRequired,true);
});
