import assert from "node:assert/strict";
import test from "node:test";
import { createMissionScheduler } from "../../apps/agentic/backend/mission-scheduler.js";

function fakeStore(){
  const missions=new Map();
  return {
    async putMission(owner,m,o={}){const key=`${owner}:${m.id}`;if(o.expectedVersion!=null){const old=missions.get(key);assert.equal(old?._storage?.version,o.expectedVersion)}missions.set(key,{...m,_storage:{version:(missions.get(key)?._storage?.version||0)+1}});return missions.get(key)},
    async getMission(owner,id){return missions.get(`${owner}:${id}`)||null},
    async listMissions(owner){return [...missions.values()].filter(m=>m.ownerId===owner)}
  };
}

test("mission executes exactly one stage per tick and schedules the next stage",async()=>{
  const store=fakeStore();let t=Date.parse("2026-10-07T00:00:00.000Z");const calls=[];
  const scheduler=createMissionScheduler({store,clock:()=>t,runWork:async(_u,workId)=>{calls.push(workId);return{status:"completed",workId}}});
  const mission=await scheduler.create("u1",{title:"V4",cadenceMs:3600000,stages:[{id:"s1",workId:"w1"},{id:"s2",workId:"w2"},{id:"s3",workId:"w3"}]});
  let r=await scheduler.runDue("u1");assert.equal(r.length,1);assert.deepEqual(calls,["w1"]);assert.equal(r[0].mission.currentStageIndex,1);assert.equal(r[0].mission.status,"scheduled");
  r=await scheduler.runDue("u1");assert.equal(r.length,0);assert.deepEqual(calls,["w1"]);
  t+=3600000;r=await scheduler.runDue("u1");assert.equal(r.length,1);assert.deepEqual(calls,["w1","w2"]);
});

test("approval blocks automatic advancement",async()=>{
  const store=fakeStore();let t=Date.parse("2026-10-07T00:00:00.000Z");let calls=0;
  const scheduler=createMissionScheduler({store,clock:()=>t,runWork:async()=>{calls++;return{status:"waiting_approval",approval:{required:true}}}});
  const mission=await scheduler.create("u1",{stages:[{id:"s1",workId:"w1"},{id:"s2",workId:"w2"}]});
  const r=await scheduler.tick("u1",mission.id);assert.equal(calls,1);assert.equal(r.mission.status,"waiting_approval");assert.equal(r.mission.currentStageIndex,0);
  t+=3600000;const again=await scheduler.tick("u1",mission.id);assert.equal(again.executed,false);assert.equal(calls,1);
});

test("failed stage stays bounded and does not advance to the next stage",async()=>{
  const store=fakeStore();let t=Date.parse("2026-10-07T00:00:00.000Z");
  const scheduler=createMissionScheduler({store,clock:()=>t,runWork:async()=>({status:"failed",error:{message:"verification failed"}})});
  const mission=await scheduler.create("u1",{stages:[{id:"s1",workId:"w1"},{id:"s2",workId:"w2"}]});
  const r=await scheduler.tick("u1",mission.id);assert.equal(r.mission.status,"failed");assert.equal(r.mission.currentStageIndex,0);assert.equal(r.mission.stages[1].state,"pending");
});


test("runDue expires overdue mission approvals before scheduling work",async()=>{
  const store=fakeStore();
  let t=Date.parse("2026-10-07T02:00:00.000Z");
  let expiryCalls=0;
  const scheduler=createMissionScheduler({
    store,
    clock:()=>t,
    approvalExpiryService:{expireDue:async(owner)=>{expiryCalls++;assert.equal(owner,"u1");return[{approval:{id:"a1",status:"expired"}}]}},
    runWork:async()=>({status:"completed"})
  });
  const mission=await scheduler.create("u1",{startAt:new Date(t+3600000).toISOString(),stages:[{id:"s1",workId:"w1"}]});
  const result=await scheduler.runDue("u1");
  assert.equal(expiryCalls,1);
  assert.equal(result.length,0);
  assert.equal(result.expiredApprovals.length,1);
  assert.equal(result.expiredApprovals[0].approval.status,"expired");
  assert.equal((await store.getMission("u1",mission.id)).status,"scheduled");
});

test("observability integrity is reconciled before stage execution",async()=>{
  const store=fakeStore();let calls=0,reconciled=0;
  const scheduler=createMissionScheduler({
    store,
    runWork:async()=>{calls++;return{status:"completed"}},
    observabilityIntegrityGate:{reconcile:async(owner,missionId)=>{reconciled++;assert.equal(owner,"u1");assert.ok(missionId);return{healthy:true,repaired:true}}}
  });
  const mission=await scheduler.create("u1",{stages:[{id:"s1",workId:"w1"}]});
  const result=await scheduler.tick("u1",mission.id);
  assert.equal(reconciled,1);assert.equal(calls,1);assert.equal(result.observabilityIntegrity.repaired,true);
});

test("observability repair failure is reported but does not block Work execution",async()=>{
  const store=fakeStore();let calls=0;
  const scheduler=createMissionScheduler({
    store,
    runWork:async()=>{calls++;return{status:"completed"}},
    observabilityIntegrityGate:{reconcile:async()=>({healthy:false,repaired:false,error:{code:"OBSERVABILITY_REPAIR_FAILED"}})}
  });
  const mission=await scheduler.create("u1",{stages:[{id:"s1",workId:"w1"}]});
  const result=await scheduler.tick("u1",mission.id);
  assert.equal(calls,1);assert.equal(result.observabilityIntegrity.healthy,false);assert.equal(result.mission.status,"completed");
});
