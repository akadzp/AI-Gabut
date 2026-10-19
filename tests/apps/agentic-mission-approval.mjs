import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionApprovalService} from '../../apps/agentic/backend/mission-approval.js';

function runtime(status='waiting_approval'){
  let mission={id:'m1',ownerId:'u1',status,currentStageIndex:0,nextRunAt:null,approval:{id:'a1',required:true,requestedAt:'2026-10-07T00:00:00.000Z'},stages:[{id:'s1',state:'waiting_approval',workId:'w1'},{id:'s2',state:'pending',workId:'w2'}],history:[],_storage:{version:1}};
  const approvals=new Map(); const reopened=[];
  const store={
    async getMission(owner,id){return owner==='u1'&&id==='m1'?mission:null},
    async putMission(owner,next){mission={...next,_storage:{version:mission._storage.version+1}};return mission},
    async putMissionApproval(_owner,a){approvals.set(a.id,a);return a},
    async getMissionApproval(_owner,id){return approvals.get(id)||null},
    async listMissionApprovals(owner){return [...approvals.values()].filter(a=>a.ownerId===owner)}
  };
  const journal={async reopen(...args){reopened.push(args);}};
  return {store,journal,reopened,mission:()=>mission,approvals};
}

test('approval grant reopens journal and reschedules the waiting stage',async()=>{
 const r=runtime(); const service=createMissionApprovalService({store:r.store,journalService:r.journal,clock:()=>Date.parse('2026-10-07T01:00:00.000Z')});
 const out=await service.approve('u1','m1','human approved');
 assert.equal(out.approval.status,'approved'); assert.equal(r.mission().status,'scheduled'); assert.equal(r.mission().stages[0].state,'pending'); assert.equal(r.mission().approval,null); assert.equal(r.reopened.length,1);
});

test('approval rejection fails only the waiting stage and mission',async()=>{
 const r=runtime(); const service=createMissionApprovalService({store:r.store});
 const out=await service.reject('u1','m1','unsafe to continue');
 assert.equal(out.approval.status,'rejected'); assert.equal(r.mission().status,'failed'); assert.equal(r.mission().stages[0].state,'failed'); assert.equal(r.mission().stages[1].state,'pending');
});

test('decision requires a live pending approval',async()=>{
 const r=runtime('scheduled'); const service=createMissionApprovalService({store:r.store});
 await assert.rejects(()=>service.approve('u1','m1'),{code:'MISSION_APPROVAL_NOT_PENDING'});
});

test('approval records are owner-scoped',async()=>{
 const r=runtime(); const service=createMissionApprovalService({store:r.store});
 await service.approve('u1','m1');
 assert.equal((await service.list('u2')).length,0);
 assert.equal((await service.list('u1')).length,1);
});
