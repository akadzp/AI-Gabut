import test from "node:test";
import assert from "node:assert/strict";
import {createMissionExecutionJournal} from "../../apps/agentic/backend/mission-execution-journal.js";
import {createMissionScheduler} from "../../apps/agentic/backend/mission-scheduler.js";

function journalStore(){
  const records=new Map();
  return {
    async getOwned(scope,owner,id){return records.get(`${scope}:${owner}:${id}`)||null},
    async putOwned(scope,owner,id,value){const key=`${scope}:${owner}:${id}`;const old=records.get(key);records.set(key,{...value,_storage:{version:(old?._storage?.version||0)+1}});return records.get(key)}
  };
}

test("journal finalizes a stage and returns the durable result on repeat begin",async()=>{
  const store=journalStore(); const journal=createMissionExecutionJournal({store});
  const started=await journal.begin("u1","m1","s1","e1");
  assert.equal(started.state,"started");
  const done=await journal.finalize("u1","m1","s1","e1","completed",{status:"completed",answer:"ok"});
  assert.equal(done.status,"completed");
  const repeat=await journal.begin("u1","m1","s1","e2");
  assert.equal(repeat.state,"completed");
  assert.equal(repeat.entry.executionId,"e1");
});

test("stale running journal can be taken over but fresh running journal conflicts",async()=>{
  let now=Date.parse("2026-10-07T00:00:00.000Z"); const store=journalStore();
  const journal=createMissionExecutionJournal({store,clock:()=>now,staleAfterMs:60000});
  await journal.begin("u1","m1","s1","e1");
  await assert.rejects(()=>journal.begin("u1","m1","s1","e2"),{code:"MISSION_EXECUTION_CONFLICT"});
  now+=61000;
  const takeover=await journal.begin("u1","m1","s1","e2");
  assert.equal(takeover.state,"started"); assert.equal(takeover.entry.executionId,"e2");
});

test("scheduler reconciles a completed journal instead of rerunning work",async()=>{
  const missions=new Map(); const records=new Map(); let puts=0; let failNext=false;
  const store={
    async putMission(owner,m,o={}){if(failNext&&m.status!=="running"){failNext=false;throw new Error("simulated persistence crash")};const key=`${owner}:${m.id}`;const old=missions.get(key);if(o.expectedVersion!=null)assert.equal(old?._storage?.version,o.expectedVersion);const saved={...m,_storage:{version:(old?._storage?.version||0)+1}};missions.set(key,saved);puts++;return saved},
    async getMission(owner,id){return missions.get(`${owner}:${id}`)||null},
    async listMissions(owner){return [...missions.values()].filter(x=>x.ownerId===owner)},
    async getOwned(scope,owner,id){return records.get(`${scope}:${owner}:${id}`)||null},
    async putOwned(scope,owner,id,v){const key=`${scope}:${owner}:${id}`;const old=records.get(key);const saved={...v,_storage:{version:(old?._storage?.version||0)+1}};records.set(key,saved);return saved}
  };
  const journal=createMissionExecutionJournal({store}); let runs=0;
  const scheduler=createMissionScheduler({store,journalService:journal,clock:()=>Date.parse("2026-10-07T00:00:00.000Z"),runWork:async()=>{runs++;return{status:"completed",value:"done"}}});
  const mission=await scheduler.create("u1",{startAt:new Date(0).toISOString(),stages:[{id:"s1",workId:"w1"}]});
  failNext=true;
  await assert.rejects(()=>scheduler.tick("u1",mission.id));
  assert.equal(runs,1);
  const stale=await store.getMission("u1",mission.id); assert.equal(stale.status,"running");
  const retry=await scheduler.tick("u1",mission.id);
  assert.equal(retry.reason,"journal_reconciled"); assert.equal(runs,1); assert.equal(retry.mission.status,"completed"); assert.equal(retry.mission.stages[0].reconciledFromJournal,true); assert.ok(puts>=2);
});
