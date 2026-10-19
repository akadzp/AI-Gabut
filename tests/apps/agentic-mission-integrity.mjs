import assert from "node:assert/strict";
import test from "node:test";
import { createMissionIntegrity } from "../../apps/agentic/backend/mission-integrity.js";

const base=(overrides={})=>({id:"m1",ownerId:"u1",status:"scheduled",currentStageIndex:0,nextRunAt:"2026-10-07T00:00:00.000Z",stages:[{id:"s1",state:"pending"},{id:"s2",state:"pending"}],...overrides});

test("valid mission passes integrity inspection",()=>{
  const integrity=createMissionIntegrity({clock:()=>Date.parse("2026-10-07T00:00:00.000Z")});
  const result=integrity.inspect("u1",base());
  assert.equal(result.valid,true);
  assert.deepEqual(result.issues,[]);
});

test("integrity detects owner, duplicate stage and lifecycle mismatches",()=>{
  const integrity=createMissionIntegrity();
  const result=integrity.inspect("u2",base({status:"running",stages:[{id:"s1",state:"pending"},{id:"s1",state:"pending"}]}));
  assert.equal(result.valid,false);
  assert.deepEqual(result.issues.map(x=>x.code),["MISSION_OWNER_MISMATCH","MISSION_STAGE_ID_DUPLICATE","MISSION_RUNNING_STAGE_MISMATCH"]);
});

test("repair normalizes bounded mission state without advancing unfinished work",()=>{
  const integrity=createMissionIntegrity({clock:()=>Date.parse("2026-10-07T00:00:00.000Z")});
  const result=integrity.repair("u1",base({status:"scheduled",currentStageIndex:99,nextRunAt:"invalid",stages:[{id:"s1",state:"pending"},{id:"s1",state:"pending"},{id:"s2",state:"pending"}]}));
  assert.equal(result.changed,true);
  assert.deepEqual(result.mission.stages.map(x=>x.id),["s1","s2"]);
  assert.equal(result.mission.currentStageIndex,1);
  assert.equal(result.mission.nextRunAt,"2026-10-07T00:00:00.000Z");
  assert.equal(result.mission.stages[1].state,"pending");
  assert.equal(result.remainingIssues.length,0);
});

test("repair preserves completed mission terminal position",()=>{
  const integrity=createMissionIntegrity();
  const result=integrity.repair("u1",base({status:"completed",currentStageIndex:0}));
  assert.equal(result.mission.currentStageIndex,2);
  assert.equal(integrity.inspect("u1",result.mission).valid,true);
});
