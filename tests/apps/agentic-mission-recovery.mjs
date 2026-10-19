import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionRecovery} from '../../apps/agentic/backend/mission-recovery.js';

test('stale running mission is re-queued when its lease is absent or expired',async()=>{
 const missions=new Map(); const leases=new Map(); let now=Date.parse('2026-10-07T00:00:00.000Z');
 const store={
  async listUsers(){return [{id:'u1'}]},
  async listMissions(owner){return [...missions.values()].filter(x=>x.ownerId===owner)},
  async putMission(owner,m){const saved={...m,_storage:{version:(missions.get(m.id)?._storage?.version||0)+1}};missions.set(m.id,saved);return saved},
  async getOwned(scope,owner,id){return leases.get(`${scope}:${owner}:${id}`)||null}
 };
 missions.set('m1',{id:'m1',ownerId:'u1',status:'running',currentStageIndex:0,updatedAt:'2026-10-06T23:00:00.000Z',stages:[{id:'s1',state:'running'}]});
 const recovery=createMissionRecovery({store,leaseService:{},clock:()=>now,staleAfterMs:60*60*1000});
 const out=await recovery.scan('u1');
 assert.equal(out.length,1); assert.equal(out[0].status,'scheduled'); assert.equal(out[0].stages[0].state,'pending'); assert.equal(out[0].stages[0].recovery.status,'interrupted');
});

test('active lease prevents stale mission recovery',async()=>{
 const missions=new Map([['m1',{id:'m1',ownerId:'u1',status:'running',currentStageIndex:0,updatedAt:'2026-10-06T23:00:00.000Z',stages:[{id:'s1',state:'running'}]}]]);
 const store={
  async listUsers(){return [{id:'u1'}]}, async listMissions(owner){return [...missions.values()].filter(x=>x.ownerId===owner)}, async putMission(){throw new Error('should not persist')},
  async getOwned(){return {executionId:'x',expiresAtMs:Date.now()+600000}}
 };
 const recovery=createMissionRecovery({store,leaseService:{},clock:()=>Date.now(),staleAfterMs:60*1000});
 const out=await recovery.scan('u1'); assert.equal(out.length,0);
});

test('fresh running mission is left untouched',async()=>{
 const missions=new Map([['m1',{id:'m1',ownerId:'u1',status:'running',currentStageIndex:0,updatedAt:new Date().toISOString(),stages:[{id:'s1',state:'running'}]}]]);
 const store={async listUsers(){return [{id:'u1'}]},async listMissions(owner){return [...missions.values()].filter(x=>x.ownerId===owner)},async putMission(){throw new Error('should not persist')},async getOwned(){return null}};
 const recovery=createMissionRecovery({store,leaseService:{},staleAfterMs:60*60*1000});
 assert.deepEqual(await recovery.scan('u1'),[]);
});
