import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionApprovalExpiryService} from '../../apps/agentic/backend/mission-approval-expiry.js';

function runtime(){
  let mission={id:'m1',ownerId:'u1',status:'waiting_approval',currentStageIndex:0,approval:{id:'a1',requestedAt:'2026-10-07T00:00:00.000Z',expiresAt:'2026-10-07T01:00:00.000Z'},stages:[{id:'s1',state:'waiting_approval',workId:'w1'}],history:[],updatedAt:'2026-10-07T00:00:00.000Z',_storage:{version:1}};
  const approvals=new Map();
  const store={
    async getMission(owner,id){return owner==='u1'&&id==='m1'?mission:null},
    async putMission(owner,next){mission={...next,_storage:{version:mission._storage.version+1}};return mission},
    async getMissionApproval(_owner,id){return approvals.get(id)||null},
    async putMissionApproval(_owner,a){approvals.set(a.id,a);return a},
    async listMissionApprovals(owner){return [...approvals.values()].filter(a=>a.ownerId===owner)},
    async listMissions(owner){return owner==='u1'?[mission]:[]}
  };
  return {store,mission:()=>mission,approvals};
}

test('expired approval transitions mission to failed and records expiry',async()=>{
 const r=runtime(); const service=createMissionApprovalExpiryService({store:r.store,clock:()=>Date.parse('2026-10-07T02:00:00.000Z')});
 const out=await service.expire('u1','m1');
 assert.equal(out.approval.status,'expired');
 assert.equal(r.mission().status,'failed');
 assert.equal(r.mission().stages[0].state,'failed');
 assert.equal(r.mission().history.at(-1).status,'approval_expired');
});

test('approval cannot expire before deadline',async()=>{
 const r=runtime(); const service=createMissionApprovalExpiryService({store:r.store,clock:()=>Date.parse('2026-10-07T00:30:00.000Z')});
 await assert.rejects(()=>service.expire('u1','m1'),{code:'MISSION_APPROVAL_NOT_EXPIRED'});
});

test('expireDue only processes expired waiting approvals',async()=>{
 const r=runtime(); const service=createMissionApprovalExpiryService({store:r.store,clock:()=>Date.parse('2026-10-07T02:00:00.000Z')});
 const out=await service.expireDue('u1');
 assert.equal(out.length,1); assert.equal(out[0].approval.status,'expired');
});
