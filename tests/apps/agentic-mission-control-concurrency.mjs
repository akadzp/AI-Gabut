import test from 'node:test';
import assert from 'node:assert/strict';
import {createMissionControl} from '../../apps/agentic/backend/mission-control.js';

function runtime(){
 let current={id:'m1',ownerId:'u1',status:'running',currentStage:14,nextStage:15,_storage:{version:1}};
 const events=[]; let conflicts=1;
 const store={
  async getOwned(_scope,_owner,id){return id===current.id?current:null;},
  async putOwned(_scope,_owner,id,value,options={}){
   if(options.expectedVersion!=null&&current._storage?.version!==options.expectedVersion){const e=new Error('VERSION_CONFLICT');e.code='VERSION_CONFLICT';throw e;}
   if(conflicts){conflicts--;current={...current,controlId:'external-control',controlHistory:[{controlId:'external-control',action:'pause',reason:'external',requestId:'external',createdAt:'2026-10-08T00:00:00.000Z'}],status:'paused',controlReason:'external',controlRequestId:'external',_storage:{version:current._storage.version+1}};const e=new Error('VERSION_CONFLICT');e.code='VERSION_CONFLICT';throw e;}
   current={...value,_storage:{version:current._storage.version+1}};return current;
  }
 };
 const observability={async event(owner,mission,type,payload){events.push({owner,mission,type,payload});return events.at(-1);},async snapshot(_owner,m){return m;}};
 return {service:createMissionControl({missionStore:store,observability,clock:()=> '2026-10-08T00:00:00.000Z'}),store,events};
}

test('version conflict is retried against fresh mission state and does not overwrite concurrent control',async()=>{
 const r=runtime();
 const result=await r.service.control('u1','m1','pause',{requestId:'req-1'});
 assert.equal(result.status,'paused');
 assert.equal(result.controlId,'external-control');
 assert.equal(result.controlRequestId,'external');
 assert.equal(r.events.length,0);
});

test('persistent version conflict fails closed without inventing a second transition',async()=>{
 let current={id:'m1',ownerId:'u1',status:'running',_storage:{version:1}};
 const store={async getOwned(){return current;},async putOwned(){const e=new Error('VERSION_CONFLICT');e.code='VERSION_CONFLICT';throw e;}};
 const observability={async event(){throw new Error('should not emit');},async snapshot(_o,m){return m;}};
 const service=createMissionControl({missionStore:store,observability});
 await assert.rejects(()=>service.control('u1','m1','pause',{requestId:'req-1'}),e=>e.code==='MISSION_CONTROL_VERSION_CONFLICT');
 assert.equal(current.status,'running');
});


test('successful transition records auditable status and storage version preconditions',async()=>{
 const current={id:'m1',ownerId:'u1',status:'running',currentStage:1,nextStage:2,_storage:{version:7}};
 const events=[];
 const store={
  async getOwned(_s,_o,id){return id===current.id?current:null;},
  async putOwned(_s,_o,id,value){Object.assign(current,value,{_storage:{version:current._storage.version+1}});return current;}
 };
 const observability={async event(_o,_m,type,payload){events.push({type,payload});},async snapshot(_o,m){return m;}};
 const service=createMissionControl({missionStore:store,observability,clock:()=> '2026-10-08T00:00:00.000Z'});
 const result=await service.control('u1','m1','pause',{requestId:'req-audit'});
 assert.equal(result.controlHistory.at(-1).fromStatus,'running');
 assert.equal(result.controlHistory.at(-1).toStatus,'paused');
 assert.equal(result.controlHistory.at(-1).baseVersion,7);
 assert.equal(events[0].payload.controlId,result.controlId);
});

test('concurrent retry never records a stale transition audit entry',async()=>{
 let current={id:'m1',ownerId:'u1',status:'paused',_storage:{version:2},controlHistory:[{controlId:'external',action:'pause',reason:'hold',requestId:'external',fromStatus:'running',toStatus:'paused',baseVersion:1,createdAt:'2026-10-08T00:00:00.000Z'}],controlId:'external',controlReason:'hold',controlRequestId:'external'};
 let first=true;
 const store={
  async getOwned(){return current;},
  async putOwned(_s,_o,_id,value,opts){
   if(first){first=false;current={...current,status:'paused',controlId:'external',controlReason:'hold',controlRequestId:'external',_storage:{version:3}};const e=new Error('VERSION_CONFLICT');e.code='VERSION_CONFLICT';throw e;}
   current={...value,_storage:{version:current._storage.version+1}};return current;
  }
 };
 const observability={async event(){},async snapshot(_o,m){return m;}};
 const service=createMissionControl({missionStore:store,observability});
 const result=await service.control('u1','m1','resume',{requestId:'req-new'});
 assert.equal(result.status,'running');
 assert.equal(result.controlHistory.at(-1).action,'resume');
 assert.equal(result.controlHistory.at(-1).fromStatus,'paused');
 assert.equal(result.controlHistory.at(-1).toStatus,'running');
 assert.equal(result.controlHistory.at(-1).baseVersion,3);
});
