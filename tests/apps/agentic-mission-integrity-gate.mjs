import assert from "node:assert/strict";
import test from "node:test";
import { createMissionIntegrity } from "../../apps/agentic/backend/mission-integrity.js";
import { createMissionIntegrityGate } from "../../apps/agentic/backend/mission-integrity-gate.js";

const base=(overrides={})=>({id:"m1",ownerId:"u1",status:"scheduled",currentStageIndex:0,nextRunAt:"2026-10-07T00:00:00.000Z",stages:[{id:"s1",state:"pending"},{id:"s2",state:"pending"}],...overrides});

function storeOf(mission){
  let current={...mission,_storage:{version:1}};
  return {
    async getMission(){return current;},
    async putMission(_owner,next){current={...next,_storage:{version:2}};return current;},
    current:()=>current
  };
}

test("gate passes valid mission without persistence",async()=>{
  const store=storeOf(base());
  const gate=createMissionIntegrityGate({store,integrity:createMissionIntegrity({clock:()=>Date.parse("2026-10-07T00:00:00.000Z")})});
  const result=await gate.ensure("u1",store.current());
  assert.equal(result.changed,false);
  assert.equal(result.repaired,false);
  assert.equal(result.mission,store.current());
});

test("gate persists bounded repair before execution",async()=>{
  const store=storeOf(base({currentStageIndex:99,nextRunAt:"invalid",stages:[{id:"s1",state:"pending"},{id:"s1",state:"pending"},{id:"s2",state:"pending"}]}));
  const gate=createMissionIntegrityGate({store,integrity:createMissionIntegrity({clock:()=>Date.parse("2026-10-07T00:00:00.000Z")})});
  const result=await gate.ensure("u1",store.current());
  assert.equal(result.repaired,true);
  assert.equal(store.current().currentStageIndex,1);
  assert.deepEqual(store.current().stages.map(s=>s.id),["s1","s2"]);
  assert.equal(store.current().stages[1].state,"pending");
});

test("gate rejects unrecoverable integrity state without running work",async()=>{
  const store=storeOf({id:"m1",ownerId:"u1",status:"unknown",currentStageIndex:0,stages:[{id:"s1",state:"pending"}]});
  const gate=createMissionIntegrityGate({store,integrity:createMissionIntegrity()});
  await assert.rejects(()=>gate.ensure("u1",store.current()),error=>error.code==="MISSION_INTEGRITY_UNREPAIRABLE");
});
