import assert from 'node:assert/strict';
import test from 'node:test';
import { createMissionRecovery } from '../../apps/agentic/backend/mission-recovery.js';

function store(){
  const missions=new Map();
  return {
    missions,
    putMission:async(o,m)=>{const saved={...m,_storage:{version:(m._storage?.version||0)+1}};missions.set(`${o}:${m.id}`,saved);return saved},
    listMissions:async o=>[...missions.values()].filter(m=>m.ownerId===o),
    listUsers:async()=>[{id:'u1'}],
    getOwned:async()=>null
  };
}

test('stale mission recovery records durable recovery evidence after persistence',async()=>{
  const s=store(),events=[];
  const clock=()=>Date.parse('2026-10-07T12:00:00.000Z');
  await s.putMission('u1',{id:'m1',ownerId:'u1',status:'running',currentStageIndex:0,stages:[{id:'s1',state:'running'}],updatedAt:'2026-10-07T10:00:00.000Z'});
  const recovery=createMissionRecovery({store:s,observability:{event:async(...args)=>events.push(args)},clock,staleAfterMs:20*60*1000});
  const out=await recovery.scan('u1');
  assert.equal(out.length,1);
  assert.equal(out[0].status,'scheduled');
  assert.equal(out[0].stages[0].state,'pending');
  assert.equal(events.length,1);
  assert.equal(events[0][2],'mission_recovered');
  assert.match(events[0][3].dedupeKey,/^mission-recovered:/);
});

test('fresh running mission does not emit recovery evidence',async()=>{
  const s=store(),events=[];
  const clock=()=>Date.parse('2026-10-07T12:00:00.000Z');
  await s.putMission('u1',{id:'m1',ownerId:'u1',status:'running',currentStageIndex:0,stages:[{id:'s1',state:'running'}],updatedAt:'2026-10-07T11:50:00.000Z'});
  const recovery=createMissionRecovery({store:s,observability:{event:async(...args)=>events.push(args)},clock,staleAfterMs:20*60*1000});
  const out=await recovery.scan('u1');
  assert.equal(out.length,0);
  assert.equal(events.length,0);
});

test('recovery evidence failure does not undo persisted recovery',async()=>{
  const s=store();
  const clock=()=>Date.parse('2026-10-07T12:00:00.000Z');
  await s.putMission('u1',{id:'m1',ownerId:'u1',status:'running',currentStageIndex:0,stages:[{id:'s1',state:'running'}],updatedAt:'2026-10-07T10:00:00.000Z'});
  const recovery=createMissionRecovery({store:s,observability:{event:async()=>{throw new Error('evidence unavailable')}},clock,staleAfterMs:20*60*1000});
  const out=await recovery.scan('u1');
  assert.equal(out.length,1);
  assert.equal(out[0].recoveryEvidenceError.message,'evidence unavailable');
  const saved=await s.missions.get('u1:m1');
  assert.equal(saved.status,'scheduled');
  assert.equal(saved.stages[0].state,'pending');
});
