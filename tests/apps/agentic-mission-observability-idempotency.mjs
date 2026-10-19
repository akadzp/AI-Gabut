import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionObservability} from '../../apps/agentic/backend/mission-observability.js';

function runtime(){
  const events=new Map();
  let now=0;
  const store={
    async putOwned(_scope,_owner,id,value,options={}){if(options.overwrite===false&&events.has(id)){const e=new Error('already exists');e.code='ALREADY_EXISTS';throw e;}events.set(id,value);return value},
    async listOwned(){return [...events.values()]}
  };
  return {events,observability:createMissionObservability({store,clock:()=>new Date(++now).toISOString()})};
}

test('dedupe key returns the original event instead of creating a duplicate',async()=>{
  const r=runtime();
  const first=await r.observability.event('u1','m1','approval_requested',{dedupeKey:'approval-requested:a1',stageId:'s1'});
  const second=await r.observability.event('u1','m1','approval_requested',{dedupeKey:'approval-requested:a1',stageId:'s1',executionId:'retry'});
  assert.equal(second.id,first.id);
  assert.equal((await r.observability.timeline('u1','m1')).length,1);
});

test('deduplicated insert remains safe when another writer wins the race',async()=>{
  const events=new Map();
  let raced=false;
  const store={
    async putOwned(_scope,_owner,id,value,options={}){
      if(options.overwrite===false&&id.includes('approval-resolved:a1-approved')&&!raced){
        raced=true;
        const winner={...value,id:'winner-event',createdAt:'2026-10-07T00:00:00.000Z',sequence:1};
        events.set(winner.id,winner);
        const error=new Error('already exists');
        error.code='ALREADY_EXISTS';
        throw error;
      }
      events.set(id,value);
      return value;
    },
    async listOwned(){return [...events.values()]}
  };
  const observability=createMissionObservability({store});
  const result=await observability.event('u1','m1','approval_resolved',{dedupeKey:'approval-resolved:a1-approved',status:'approved'});
  assert.equal(result.id,'winner-event');
  assert.equal((await observability.timeline('u1','m1')).length,1);
});

test('timeline uses stable sequence ordering rather than lexical timestamps alone',async()=>{
  const r=runtime();
  await r.observability.event('u1','m1','stage_started',{dedupeKey:'a'});
  await r.observability.event('u1','m1','stage_completed',{dedupeKey:'b'});
  const timeline=await r.observability.timeline('u1','m1');
  assert.deepEqual(timeline.map(x=>x.sequence),[1,2]);
  assert.deepEqual(timeline.map(x=>x.type),['stage_started','stage_completed']);
});

test('dedupe keys are scoped to the mission timeline',async()=>{
  const r=runtime();
  const a=await r.observability.event('u1','m1','checkpoint_saved',{dedupeKey:'checkpoint:1'});
  const b=await r.observability.event('u1','m2','checkpoint_saved',{dedupeKey:'checkpoint:1'});
  assert.notEqual(a.id,b.id);
  assert.equal((await r.observability.timeline('u1','m1')).length,1);
  assert.equal((await r.observability.timeline('u1','m2')).length,1);
});
