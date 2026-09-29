import assert from "node:assert/strict";
import test from "node:test";
import { createRealtimeService } from "../../apps/agentic/backend/realtime.js";

function storeOf(eventsByOwner){return{listActivities:async owner=>(eventsByOwner.get(owner)||[])}} 
const event=(id,createdAt,owner="a",executionId="e1")=>({id,createdAt,ownerId:owner,executionId,sessionId:"s1",action:id,status:"running",label:id,meta:{step:id},error:null,type:"activity"});

test("realtime replay is ordered and resumes after cursor",async()=>{
  const events=[event("b","2026-01-01T00:00:02.000Z"),event("a","2026-01-01T00:00:01.000Z")];
  const svc=createRealtimeService({store:storeOf(new Map([["a",events]]))});
  const first=await svc.replay("a");
  assert.deepEqual(first.map(x=>x.id),["a","b"]);
  const next=await svc.replay("a",{after:first[0].cursor});
  assert.deepEqual(next.map(x=>x.id),["b"]);
});

test("realtime subscribers are owner and filter isolated",async()=>{
  const svc=createRealtimeService({store:storeOf(new Map())});
  const gotA=[],gotB=[];
  svc.subscribe("a",x=>gotA.push(x),{executionId:"e1"});
  svc.subscribe("b",x=>gotB.push(x));
  await svc.publish("a",event("a1","2026-01-01T00:00:01.000Z","a","e1"));
  await svc.publish("a",event("a2","2026-01-01T00:00:02.000Z","a","e2"));
  assert.deepEqual(gotA.map(x=>x.id),["a1"]);
  assert.deepEqual(gotB,[]);
});
