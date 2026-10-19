import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';

function runtime(initial={id:'m1',ownerId:'u1',status:'running',currentStage:14,nextStage:15}){
  const records=new Map([['missions:u1:m1',initial]]);
  const store={
    async getOwned(scope,owner,id){return records.get(`${scope}:${owner}:${id}`)||null},
    async putOwned(scope,owner,id,v){records.set(`${scope}:${owner}:${id}`,v);return v}
  };
  const events=[];
  const observability={async event(ownerId,missionId,type,payload){events.push({ownerId,missionId,type,payload});return events.at(-1)},async snapshot(ownerId,m){return {missionId:m.id,ownerId,status:m.status}}};
  return {service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-07T07:00:00.000Z'}),store,events};
}

test('pause and resume retain semantic stage lifecycle evidence',async()=>{
  const r=runtime();
  await r.service.control('u1','m1','pause','operator hold');
  await r.service.control('u1','m1','resume','continue');
  assert.deepEqual(r.events.map(x=>x.type),['stage_paused','stage_resumed']);
  assert.equal((await r.store.getOwned('missions','u1','m1')).status,'running');
});

test('cancel emits mission_cancelled rather than stage_failed',async()=>{
  const r=runtime();
  await r.service.control('u1','m1','cancel','operator stop');
  assert.equal(r.events[0].type,'mission_cancelled');
  assert.equal(r.events[0].payload.action,'cancel');
  assert.equal((await r.store.getOwned('missions','u1','m1')).status,'cancelled');
});

test('control remains owner-scoped and terminal cancellation cannot repeat',async()=>{
  const r=runtime();
  await assert.rejects(()=>r.service.control('u2','m1','pause'),{code:'MISSION_NOT_FOUND'});
  await r.service.control('u1','m1','cancel');
  await assert.rejects(()=>r.service.control('u1','m1','cancel'),{code:'INVALID_STATE'});
});
