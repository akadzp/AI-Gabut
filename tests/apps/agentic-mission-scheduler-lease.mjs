import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionScheduler} from '../../apps/agentic/backend/mission-scheduler.js';
import {createMissionExecutionLease} from '../../apps/agentic/backend/mission-execution-lease.js';

function runtime(){
 const missions=new Map();
 const leases=new Map();
 let now=Date.now();
 const store={
  async putMission(owner,m,o={}){missions.set(`${owner}:${m.id}`,{...m,_storage:{version:(missions.get(`${owner}:${m.id}`)?._storage?.version||0)+1}});return missions.get(`${owner}:${m.id}`)},
  async getMission(owner,id){return missions.get(`${owner}:${id}`)||null},
  async listMissions(owner){return [...missions.values()].filter(x=>x.ownerId===owner)},
  async getOwned(scope,owner,id){return leases.get(`${scope}:${owner}:${id}`)||null},
  async putOwned(scope,owner,id,v){leases.set(`${scope}:${owner}:${id}`,v);return v}
 };
 const lease=createMissionExecutionLease({leaseStore:store,clock:()=>new Date(now).toISOString(),leaseMs:60000});
 const scheduler=createMissionScheduler({store,leaseService:lease,clock:()=>now,runWork:async()=>({status:'completed'})});
 return {store,scheduler,setNow(v){now=v}};
}

test('mission execution acquires and releases a lease around a stage',async()=>{
 const r=runtime(); const m=await r.scheduler.create('u1',{stages:[{id:'s1',title:'Stage 1',workId:'w1'}],startAt:new Date(0).toISOString()});
 const out=await r.scheduler.tick('u1',m.id,{at:Date.now()});
 assert.equal(out.executed,true); assert.equal(out.result.status,'completed');
 assert.equal((await r.store.getOwned('mission-leases','u1',`mission-lease:u1:${m.id}`)).releasedAt!==undefined,true);
});

test('an active lease blocks a second scheduler execution',async()=>{
 const r=runtime(); const m=await r.scheduler.create('u1',{stages:[{id:'s1',title:'Stage 1',workId:'w1'}],startAt:new Date(0).toISOString()});
 await r.store.putOwned('mission-leases','u1',`mission-lease:u1:${m.id}`,{executionId:'other',expiresAtMs:Date.now()+60000});
 await assert.rejects(()=>r.scheduler.tick('u1',m.id,{at:Date.now()}),{code:'LEASE_CONFLICT'});
});
