import test from 'node:test';
import assert from 'node:assert/strict';
import { createCollaborationService } from '../../apps/agentic/backend/collaboration.js';

function runtime(){
  const records=new Map();
  const store={
    async putOwned(scope,owner,id,value){records.set(`${scope}:${owner}:${id}`,value);return value},
    async listOwned(scope,owner){return [...records.values()].filter(x=>x.ownerId===owner&&scope==='collaboration')}
  };
  const calls=[];
  const work={raw:async(owner,id)=>({id,ownerId:owner,state:'running'})};
  const workExecution={
    revise:async(owner,id,instruction)=>{calls.push(['revise',owner,id,instruction]);return {id,state:'paused'}},
    pause:async(owner,id,reason)=>{calls.push(['pause',owner,id,reason]);return {id,state:'paused'}},
    resume:async(owner,id,options)=>{calls.push(['resume',owner,id,options]);return {id,state:'running'}}
  };
  const published=[];
  const realtime={publish:async(owner,event)=>published.push([owner,event])};
  return {service:createCollaborationService({store,work,workExecution,realtime}),store,calls,published};
}

test('collaboration persists feedback with provenance and owner scope',async()=>{
  const r=runtime();const item=await r.service.feedback('u1','w1','Use existing API only');
  assert.equal(item.type,'feedback');assert.equal(item.provenance.ownerId,'u1');assert.equal(item.provenance.actor,'user');
  assert.equal((await r.service.list('u1','w1')).length,1);assert.equal(r.published.length,1);
});

test('instruction refinement and correction reuse execution authority',async()=>{
  const r=runtime();await r.service.refine('u1','w1','Narrow scope to backend');await r.service.correct('u1','w1','Do not change frontend');
  assert.deepEqual(r.calls.map(x=>x[0]),['revise','revise']);
  assert.equal((await r.service.list('u1','w1')).length,2);
});

test('pause and resume preserve collaboration boundary',async()=>{
  const r=runtime();await r.service.pause('u1','w1','Need human review');await r.service.resume('u1','w1',{checkpoint:true});
  assert.deepEqual(r.calls.map(x=>x[0]),['pause','resume']);
  const items=await r.service.list('u1','w1');assert.deepEqual(items.map(x=>x.payload.action),['pause','resume']);
});
