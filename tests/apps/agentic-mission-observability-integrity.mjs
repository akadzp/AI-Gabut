import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionObservability} from '../../apps/agentic/backend/mission-observability.js';

function runtime(items=[]){
 const events=new Map(items.map(x=>[x.id,x]));
 const store={async putOwned(_s,_o,id,v){events.set(id,v);return v},async listOwned(_s,o){return [...events.values()].filter(x=>x.ownerId===o)},async removeOwned(_s,_o,id){return events.delete(id)}};
 return {events,obs:createMissionObservability({store,clock:()=> '2026-10-07T00:00:00.000Z'})};
}

test('inspect reports duplicate sequence and dedupe anomalies',async()=>{
 const r=runtime([
  {id:'a',ownerId:'u',missionId:'m',type:'stage_started',dedupeKey:'a',sequence:1,createdAt:'2026-01-01'},
  {id:'b',ownerId:'u',missionId:'m',type:'stage_completed',dedupeKey:'a',sequence:1,createdAt:'2026-01-02'}
 ]);
 const x=await r.obs.inspect('u','m');
 assert.equal(x.healthy,false);
 assert.ok(x.issues.some(i=>i.code==='DUPLICATE_SEQUENCE'));
 assert.ok(x.issues.some(i=>i.code==='DUPLICATE_DEDUPE_KEY'));
});

test('repair rebuilds a contiguous mission timeline without changing event types',async()=>{
 const r=runtime([
  {id:'b',ownerId:'u',missionId:'m',type:'stage_completed',dedupeKey:'b',sequence:9,createdAt:'2026-01-02'},
  {id:'a',ownerId:'u',missionId:'m',type:'stage_started',dedupeKey:'a',sequence:9,createdAt:'2026-01-01'}
 ]);
 const out=await r.obs.repair('u','m');
 assert.equal(out.repaired,true);
 assert.deepEqual((await r.obs.timeline('u','m')).map(x=>x.sequence),[1,2]);
 assert.deepEqual((await r.obs.timeline('u','m')).map(x=>x.type),['stage_started','stage_completed']);
});

test('repair drops duplicate dedupe evidence but preserves the earliest event',async()=>{
 const r=runtime([
  {id:'a',ownerId:'u',missionId:'m',type:'checkpoint_saved',dedupeKey:'c',sequence:1,createdAt:'2026-01-01'},
  {id:'b',ownerId:'u',missionId:'m',type:'checkpoint_saved',dedupeKey:'c',sequence:2,createdAt:'2026-01-02'}
 ]);
 await r.obs.repair('u','m');
 const t=await r.obs.timeline('u','m');
 assert.equal(t.length,1); assert.equal(t[0].id,'a');
});

test('repair is owner-scoped and does not mutate another owner timeline',async()=>{
 const r=runtime([
  {id:'x',ownerId:'other',missionId:'m',type:'stage_started',sequence:7,createdAt:'2026-01-01'},
  {id:'a',ownerId:'u',missionId:'m',type:'stage_started',sequence:4,createdAt:'2026-01-02'}
 ]);
 await r.obs.repair('u','m');
 assert.equal((await r.obs.timeline('u','m'))[0].sequence,1);
 assert.equal((await r.obs.timeline('other','m'))[0].sequence,7);
});
