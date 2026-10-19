import assert from 'node:assert/strict';
import test from 'node:test';
import { createMissionObservabilityIntegrityGate } from '../../apps/agentic/backend/mission-observability-integrity-gate.js';

test('gate reconciles unhealthy evidence before mission execution without changing authority',async()=>{
 let repairs=0,published=[];
 const observability={
  inspect:async()=> repairs?{healthy:true,eventCount:2,issues:[]}:{healthy:false,eventCount:2,issues:[{code:'DUPLICATE_SEQUENCE'}]},
  repair:async()=>{repairs++;return {repaired:true}}
 };
 const gate=createMissionObservabilityIntegrityGate({observability,realtime:{publish:async(_o,e)=>published.push(e)},clock:()=>0});
 const result=await gate.reconcile('u1','m1');
 assert.equal(result.repaired,true);
 assert.equal(result.healthy,true);
 assert.equal(repairs,1);
 assert.equal(published[0].type,'mission.observability.repaired');
});

test('gate does not block execution when evidence repair fails',async()=>{
 const observability={inspect:async()=>({healthy:false,eventCount:1,issues:[{code:'INVALID_EVENT_TYPE'}]}),repair:async()=>{throw new Error('storage unavailable')}};
 const gate=createMissionObservabilityIntegrityGate({observability});
 const result=await gate.reconcile('u1','m1');
 assert.equal(result.healthy,false);
 assert.equal(result.repaired,false);
 assert.equal(result.error.code,'OBSERVABILITY_REPAIR_FAILED');
});

test('healthy evidence is a no-op',async()=>{
 let called=0;
 const observability={inspect:async()=>({healthy:true,eventCount:0,issues:[]}),repair:async()=>{called++}};
 const gate=createMissionObservabilityIntegrityGate({observability});
 const result=await gate.reconcile('u1','m1');
 assert.equal(result.healthy,true);
 assert.equal(result.repaired,false);
 assert.equal(called,0);
});
