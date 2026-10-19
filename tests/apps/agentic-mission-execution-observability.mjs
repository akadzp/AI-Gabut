import assert from 'node:assert/strict';
import test from 'node:test';
import { createMissionScheduler } from '../../apps/agentic/backend/mission-scheduler.js';

function store(){
 const missions=new Map();
 return {putMission:async(o,m)=>{const saved={...m,_storage:{version:(m._storage?.version||0)+1}};missions.set(`${o}:${m.id}`,saved);return saved},getMission:async(o,id)=>missions.get(`${o}:${id}`),listMissions:async o=>[...missions.values()].filter(m=>m.ownerId===o)};
}

test('scheduler records stage and mission completion evidence after persistence',async()=>{
 const s=store(),events=[];
 const scheduler=createMissionScheduler({store:s,runWork:async()=>({status:'completed',value:'ok'}),observability:{event:async(_o,_m,type,payload)=>events.push({type,payload})},clock:()=>Date.parse('2026-10-07T12:00:00.000Z'),cadenceMs:60000});
 const m=await scheduler.create('u1',{title:'T',stages:[{id:'s1',title:'S1'}]});
 const r=await scheduler.tick('u1',m.id,{at:Date.parse('2026-10-07T12:00:00.000Z')});
 assert.equal(r.mission.status,'completed');
 assert.deepEqual(events.map(x=>x.type),['stage_started','stage_completed','mission_completed']);
 assert.equal(events[1].payload.dedupeKey,`stage-completed:${events[1].payload.executionId}`);
 assert.equal(events[2].payload.dedupeKey,`mission-completed:${m.id}`);
});

test('failed stage produces durable failure evidence after state persistence',async()=>{
 const s=store(),events=[];
 const scheduler=createMissionScheduler({store:s,runWork:async()=>({status:'failed',error:{code:'X',message:'boom'}}),observability:{event:async(_o,_m,type,payload)=>events.push({type,payload})}});
 const m=await scheduler.create('u1',{stages:[{id:'s1'}]});
 const r=await scheduler.tick('u1',m.id,{at:Date.now()});
 assert.equal(r.mission.status,'failed');
 assert.deepEqual(events.map(x=>x.type),['stage_started','stage_failed']);
 assert.equal(events[1].payload.error.code,'X');
});

test('waiting approval records approval evidence and not stage completion',async()=>{
 const s=store(),events=[];
 const scheduler=createMissionScheduler({store:s,runWork:async()=>({status:'waiting_approval',approval:{required:true,id:'a1'}}),observability:{event:async(_o,_m,type,payload)=>events.push({type,payload})}});
 const m=await scheduler.create('u1',{stages:[{id:'s1'}]});
 const r=await scheduler.tick('u1',m.id,{at:Date.now()});
 assert.equal(r.mission.status,'waiting_approval');
 assert.deepEqual(events.map(x=>x.type),['stage_started','approval_requested']);
});
